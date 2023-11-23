#![deny(clippy::all)]
#![warn(clippy::pedantic)]
// TODO: Remove missing errors doc lint from allow list
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

#[derive(Debug, thiserror::Error)]
pub enum ParseReplyError {
    #[error("{0}")]
    SubMsgFailure(String),
    #[error("reply data missing")]
    ReplyDataMissing,
    #[error(transparent)]
    CosmwasmStd(#[from] cosmwasm_std::StdError),
}

pub mod types {
    use cosmwasm_std::Coin;
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct RawCoin {
        #[prost(string, tag = "1")]
        pub denom: String,
        #[prost(string, tag = "2")]
        pub amount: String,
    }

    impl From<Coin> for RawCoin {
        fn from(value: Coin) -> Self {
            Self {
                denom: value.denom,
                amount: value.amount.to_string(),
            }
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct MsgData {
        #[prost(string, tag = "1")]
        pub msg_type: String,
        #[prost(bytes = "vec", tag = "2")]
        pub data: Vec<u8>,
    }
}

pub mod icq {
    use cosmwasm_std::{from_json, Binary, Coin, CustomQuery, Deps, QueryRequest, Reply, StdError};
    use neutron_sdk::{
        bindings::{query::NeutronQuery, types::RegisteredQuery},
        interchain_queries::{check_query_type, get_registered_query, types::QueryType},
        NeutronError,
    };

    use crate::ParseReplyError;

    pub fn deposit_fee(deps: Deps<impl CustomQuery>) -> Result<Coin, StdError> {
        #[cosmwasm_schema::cw_serde]
        struct Params {
            query_submit_timeout: String,
            query_deposit: Vec<Coin>,
            tx_query_removal_limit: String,
        }

        #[cosmwasm_schema::cw_serde]
        struct QueryParamsResponse {
            params: Params,
        }

        let res: QueryParamsResponse = deps.querier.query(&QueryRequest::Stargate {
            path: "/neutron.interchainqueries.Query/Params".to_owned(),
            data: Binary(vec![]),
        })?;

        let coin = res
            .params
            .query_deposit
            .into_iter()
            .next()
            .expect("there should always be a deposit coin");

        Ok(coin)
    }

    /// Tries to parse the query id of a newly registered ICQ from the reply data
    pub fn parse_registration_reply(reply: Reply) -> Result<u64, ParseReplyError> {
        #[cosmwasm_schema::cw_serde]
        struct MsgRegisterInterchainQueryResponse {
            id: u64,
        }

        let res = reply
            .result
            .into_result()
            .map_err(ParseReplyError::SubMsgFailure)?;

        let data = res.data.ok_or(ParseReplyError::ReplyDataMissing)?;

        let msg: MsgRegisterInterchainQueryResponse = from_json(data)?;

        Ok(msg.id)
    }

    pub fn updated_registered_kv_query(
        deps: Deps<NeutronQuery>,
        query_id: u64,
    ) -> Result<Option<RegisteredQuery>, NeutronError> {
        let res = get_registered_query(deps, query_id)?;

        let registered_query = res.registered_query;

        let last_submitted_local_height = registered_query.last_submitted_result_local_height;

        if last_submitted_local_height == 0 {
            return Ok(None);
        }

        check_query_type(registered_query.query_type, QueryType::KV)?;

        Ok(Some(registered_query))
    }
}

pub mod interchain_tx {
    use std::num::NonZeroU32;

    use cosmwasm_std::{from_json, Addr, BankMsg, Coin, Deps, MessageInfo, Reply};
    use neutron_sdk::{
        bindings::{msg::IbcFee, query::NeutronQuery, types::ProtobufAny},
        query::min_ibc_fee::query_min_ibc_fee,
        NeutronError,
    };
    use prost::Message;
    use serde::Serialize;

    use crate::{
        types::{MsgData, RawCoin},
        ParseReplyError,
    };

    pub static IBC_FEE_DENOM: &str = "untrn";

    pub fn ibc_fee(deps: Deps<NeutronQuery>) -> Result<IbcFee, NeutronError> {
        query_min_ibc_fee(deps).map(|res| res.min_fee)
    }

    #[must_use]
    pub fn is_ibc_fee_covered(info: &MessageInfo, ibc_fee: &IbcFee, tx_count: NonZeroU32) -> bool {
        assert_eq!(ibc_fee.ack_fee.len(), 1, "only a single ibc ack fee asset");
        assert_eq!(
            ibc_fee.timeout_fee.len(),
            1,
            "only a single ibc timeout fee asset"
        );

        let Some(attached_fee_coin_amount) = info
            .funds
            .iter()
            .find_map(|c| (c.denom == IBC_FEE_DENOM).then_some(c.amount.u128()))
        else {
            return false;
        };

        let total_fee_amount_per_tx: u128 = ibc_fee
            .timeout_fee
            .iter()
            .chain(ibc_fee.ack_fee.iter())
            .filter_map(|c| (c.denom == IBC_FEE_DENOM).then_some(c.amount.u128()))
            .sum();

        attached_fee_coin_amount >= (total_fee_amount_per_tx * u128::from(tx_count.get()))
    }

    #[must_use]
    pub fn refund_ibc_fee_msg(
        recipient: String,
        ibc_fee: &IbcFee,
        tx_count: NonZeroU32,
    ) -> BankMsg {
        assert_eq!(ibc_fee.ack_fee.len(), 1, "only a single ibc ack fee asset");
        assert_eq!(
            ibc_fee.timeout_fee.len(),
            1,
            "only a single ibc timeout fee asset"
        );

        let total_fee_amount_per_tx: u128 = ibc_fee
            .timeout_fee
            .iter()
            .chain(ibc_fee.ack_fee.iter())
            .filter_map(|c| (c.denom == IBC_FEE_DENOM).then_some(c.amount.u128()))
            .sum();

        let refund_amount = total_fee_amount_per_tx * u128::from(tx_count.get());

        BankMsg::Send {
            to_address: recipient,
            amount: cosmwasm_std::coins(refund_amount, IBC_FEE_DENOM),
        }
    }

    pub fn delegate_msg(
        delegator: impl Into<String>,
        validator: impl Into<String>,
        token: Coin,
    ) -> ProtobufAny {
        #[derive(Clone, PartialEq, prost::Message)]
        struct MsgDelegate {
            #[prost(string, tag = "1")]
            delegator_address: String,
            #[prost(string, tag = "2")]
            validator_address: String,
            #[prost(message, optional, tag = "3")]
            amount: Option<RawCoin>,
        }

        fn build_msg(
            delegator_address: String,
            validator_address: String,
            raw_coin: RawCoin,
        ) -> ProtobufAny {
            let delegate_msg = MsgDelegate {
                delegator_address,
                validator_address,
                amount: Some(raw_coin),
            };

            let encoded = delegate_msg.encode_to_vec();

            ProtobufAny {
                type_url: "/cosmos.staking.v1beta1.MsgDelegate".to_string(),
                value: encoded.into(),
            }
        }

        build_msg(delegator.into(), validator.into(), token.into())
    }

    pub fn undelegate_msg(
        delegator: impl Into<String>,
        validator: impl Into<String>,
        token: Coin,
    ) -> ProtobufAny {
        #[derive(Clone, PartialEq, prost::Message)]
        struct MsgUndelegate {
            #[prost(string, tag = "1")]
            delegator_address: String,
            #[prost(string, tag = "2")]
            validator_address: String,
            #[prost(message, optional, tag = "3")]
            amount: Option<RawCoin>,
        }

        fn build_msg(
            delegator_address: String,
            validator_address: String,
            raw_coin: RawCoin,
        ) -> ProtobufAny {
            let delegate_msg = MsgUndelegate {
                delegator_address,
                validator_address,
                amount: Some(raw_coin),
            };

            let encoded = delegate_msg.encode_to_vec();

            ProtobufAny {
                type_url: "/cosmos.staking.v1beta1.MsgUndelegate".to_string(),
                value: encoded.into(),
            }
        }

        build_msg(delegator.into(), validator.into(), token.into())
    }

    static WITHDRAW_REWARDS_TYPE_URL: &str =
        "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward";

    pub fn withdraw_rewards_msg(
        delegator: impl Into<String>,
        validator: impl Into<String>,
    ) -> ProtobufAny {
        #[derive(Clone, PartialEq, prost::Message)]
        struct MsgWithdrawDelegatorReward {
            #[prost(string, tag = "1")]
            delegator_address: String,
            #[prost(string, tag = "2")]
            validator_address: String,
        }

        fn build_msg(delegator_address: String, validator_address: String) -> ProtobufAny {
            let delegate_msg = MsgWithdrawDelegatorReward {
                delegator_address,
                validator_address,
            };

            let encoded = delegate_msg.encode_to_vec();

            ProtobufAny {
                type_url: WITHDRAW_REWARDS_TYPE_URL.to_owned(),
                value: encoded.into(),
            }
        }

        build_msg(delegator.into(), validator.into())
    }

    pub fn parse_withdraw_rewards_response(
        msg_data: &MsgData,
        denom: &str,
    ) -> Result<Option<Coin>, prost::DecodeError> {
        #[derive(Clone, PartialEq, Message)]
        struct WithdrawRewardResponse {
            /// Since: cosmos-sdk 0.46
            #[prost(message, repeated, tag = "1")]
            amount: Vec<RawCoin>,
        }

        if msg_data.msg_type != WITHDRAW_REWARDS_TYPE_URL {
            return Ok(None);
        }

        let response = WithdrawRewardResponse::decode(msg_data.data.as_slice())?;

        let Some(coin) = response.amount.into_iter().find(|coin| coin.denom == denom) else {
            return Ok(None);
        };

        let coin = coin
            .amount
            .parse()
            .map(|amount| cosmwasm_std::coin(amount, coin.denom))
            .expect("infallible reward coin amount parsing");

        Ok(Some(coin))
    }

    pub fn bank_send_msg(
        from_address: impl Into<String>,
        to_address: impl Into<String>,
        token: Coin,
    ) -> ProtobufAny {
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct MsgSend {
            #[prost(string, tag = "1")]
            from_address: String,
            #[prost(string, tag = "2")]
            to_address: String,
            #[prost(message, repeated, tag = "3")]
            amount: Vec<RawCoin>,
        }

        fn build_msg(from_address: String, to_address: String, raw_coin: RawCoin) -> ProtobufAny {
            let delegate_msg = MsgSend {
                from_address,
                to_address,
                amount: vec![raw_coin],
            };

            let encoded = delegate_msg.encode_to_vec();

            ProtobufAny {
                type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                value: encoded.into(),
            }
        }

        build_msg(from_address.into(), to_address.into(), token.into())
    }

    pub fn ibc_transfer_with_hook_msg<Msg: Serialize>(
        source_channel: String,
        token: Coin,
        sender: String,
        timeout_timestamp_nanos: u64,
        contract: Addr,
        msg: Msg,
    ) -> ProtobufAny {
        #[derive(Clone, PartialEq, Message)]
        struct Height {
            #[prost(uint64, tag = "1")]
            revision_number: u64,
            #[prost(uint64, tag = "2")]
            revision_height: u64,
        }

        #[derive(Clone, PartialEq, Message)]
        struct MsgTransfer {
            #[prost(string, tag = "1")]
            source_port: String,
            #[prost(string, tag = "2")]
            source_channel: String,
            #[prost(message, optional, tag = "3")]
            token: Option<RawCoin>,
            #[prost(string, tag = "4")]
            sender: String,
            #[prost(string, tag = "5")]
            receiver: String,
            #[prost(message, optional, tag = "6")]
            timeout_height: Option<Height>,
            #[prost(uint64, tag = "7")]
            timeout_timestamp: u64,
            #[prost(string, tag = "8")]
            memo: String,
        }

        #[derive(Serialize)]
        struct IbcHookWasm<Msg> {
            contract: String,
            msg: Msg,
        }

        #[derive(Serialize)]
        struct IbcHookMemo<Msg> {
            wasm: IbcHookWasm<Msg>,
        }

        let ibc_hook = IbcHookMemo {
            wasm: IbcHookWasm {
                contract: contract.clone().into_string(),
                msg,
            },
        };

        let memo = cosmwasm_std::to_json_string(&ibc_hook).expect("infallible serialization");

        let transfer_msg = MsgTransfer {
            source_port: "transfer".to_owned(),
            source_channel,
            token: Some(token.into()),
            sender,
            receiver: contract.into_string(),
            timeout_height: None,
            timeout_timestamp: timeout_timestamp_nanos,
            memo,
        };

        ProtobufAny {
            type_url: "/ibc.applications.transfer.v1.MsgTransfer".to_owned(),
            value: transfer_msg.encode_to_vec().into(),
        }
    }

    #[cosmwasm_schema::cw_serde]
    pub struct IssueTxResponse {
        pub sequence_id: u64,
        pub channel: String,
    }

    /// Tries to parse the sequence number and channel id of a newly issued IBC tx from the reply data
    pub fn parse_issue_tx_reply(reply: Reply) -> Result<IssueTxResponse, ParseReplyError> {
        let res = reply
            .result
            .into_result()
            .map_err(ParseReplyError::SubMsgFailure)?;

        let data = res.data.ok_or(ParseReplyError::ReplyDataMissing)?;

        from_json(data).map_err(ParseReplyError::from)
    }

    pub fn decode_sudo_response_data(data: &[u8]) -> Result<Vec<MsgData>, prost::DecodeError> {
        #[derive(prost::Message)]
        struct TxMsgData {
            #[prost(message, repeated, tag = "1")]
            data: Vec<MsgData>,
        }

        TxMsgData::decode(data).map(|tx| tx.data)
    }
}

pub mod ica {
    use cosmwasm_std::StdError;

    #[cosmwasm_schema::cw_serde]
    pub struct OpenAckVersion {
        pub version: String,
        pub controller_connection_id: String,
        pub host_connection_id: String,
        pub address: String,
        pub encoding: String,
        pub tx_type: String,
    }

    pub fn parse_counterparty_version(
        counterparty_version: &str,
    ) -> Result<OpenAckVersion, StdError> {
        cosmwasm_std::from_json(counterparty_version.as_bytes())
    }
}
