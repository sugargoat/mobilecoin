// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for transaction history

use crate::{database_key::DatabaseByteArrayKey, error::Error, utxo_store::UtxoId};

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use prost::{Enumeration, Message};
use std::sync::Arc;
use mc_transaction_core::tx::TxHash;

// LMDB Database Names
pub const TRANSACTION_DB_NAME: &str = "mobilecoind_db:transaction_history_store:transaction_data";

pub type TxId = DatabaseByteArrayKey;

impl From<&TxHash> for TxId {
    fn from(src: &TxHash) -> TxId {
        Self {
            Self::from(src.as_bytes())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Enumeration)]
pub enum TxStatus {
    Success = 0,
    Failure = 1,
    Pending = 2,
}

/// The Transaction Data associated with a transaction in the transaction history.
#[derive(Message, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TransactionData {
    /// The outputs for this transaction
    #[prost(bytes, repeated, tag = "1")]
    pub transaction_outputs: Vec<UtxoId>,

    /// The index of the change output
    #[prost(uint32, repeated, tag = "2")]
    pub change_index: u32,

    /// The sender account, if this transaction was sent from this wallet.
    #[prost(bytes, tag = "3")]
    pub sender_account: Option<MonitorId>,

    /// The sender comment associated with the subaddress, if the transaction was
    /// received by this wallet.
    #[prost(string, tag = "4")]
    pub sender_alias: Option<String>,

    /// The receiver public address.
    #[prost(string, tag = "5")]
    pub receiver: String,

    /// The subaddress index at which the change was received
    #[prost(uint64, tag = "6")]
    pub change_receiver: u64,

    #[prost(uint64, tag = "7")]
    pub value: u64,

    #[prost(uint64, tag = "8")]
    pub fee: u64,

    #[prost(enumeration = "TxStatus", tag = "9")]
    pub status: TxStatus,

    /// The time at which this transaction was created and submitted.
    /// In seconds since UNIX_EPOCH.
    #[prost(uint64, tag = "10")]
    pub create_time: u64,

    /// Comment associated with this public address.
    #[prost(string, tag = "11")]
    pub comment: String,

    #[prost(uint64, tag = "12")]
    pub height: u64,
}

/// Storage for Transaction History.
#[derive(Clone)]
pub struct TransactionHistoryStore {
    /// Environment for LMDB transactions.
    env: Arc<Environment>,

    /// Mapping of TxId -> Address Data.
    transaction_data: Database,

    /// Logger.
    logger: Logger,
}

impl TransactionHistoryStore {
    /// Create a new TransactionHistoryStore.
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let transaction_data = env.create_db(Some(TRANSACTION_DB_NAME), DatabaseFlags::empty())?;
        Ok(Self {
            env,
            transaction_data,
            logger,
        })
    }

    /// Insert a new Transaction into the database.
    /// Allows overwriting for updates. FIXME: make sure this is tested
    pub fn insert<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        tx_id: &TxId,
        data: &AddressData,
    ) -> Result<(), Error> {
        let address_db_key = mc_util_serial::encode(address);

        let value_bytes = mc_util_serial::encode(data);
        db_txn.put(
            self.address_data,
            &address_db_key,
            &value_bytes,
            WriteFlags::empty(),
        )?;

        log::trace!(
            self.logger,
            "Inserting {:?} ({:?}) to address store",
            address,
            data,
        );

        Ok(())
    }

    #[allow(unused)] // FIXME: currently only used in test
    /// Returns the Address Data associated with a given public address
    /// FIXME: deal with duplicates/overwrites
    pub fn get(
        &self,
        db_txn: &impl Transaction,
        address: &PublicAddress,
    ) -> Result<AddressData, Error> {
        let address_db_key = mc_util_serial::encode(address);
        match db_txn.get(self.address_data, &address_db_key) {
            Ok(value_bytes) => Ok(mc_util_serial::decode(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::AddressNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /*
    /// Delete the data stored for a public address
    pub fn delete<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        address: &PublicAddress,
    ) -> Result<(), Error> {
        let address_db_key = mc_util_serial::encode(address);

        db_txn.del(self.address_data, &address_db_key, None)?;

        Ok(())
    }

     */
    pub fn list_addresses(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<HashMap<PublicAddress, AddressData>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.address_data)?;
        Ok(cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, value_bytes)| {
                        Ok((
                            mc_util_serial::decode(key_bytes)
                                .map_err(|_| Error::KeyDeserializationError)?,
                            mc_util_serial::decode(value_bytes)
                                .map_err(|_| Error::KeyDeserializationError)?,
                        ))
                    })
            })
            .collect::<Result<HashMap<_, _>, Error>>()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_test_monitor_data_and_id;
    use mc_common::logger::{test_with_logger, Logger};
    use rand::{rngs::StdRng, SeedableRng};
    use tempdir::TempDir;

    #[test_with_logger]
    fn test_insert_and_get(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let db_tmp = TempDir::new("account_store_db").expect("Could not make tempdir for test");
        let db_path = db_tmp
            .path()
            .to_str()
            .expect("Could not get path as string");

        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(10000000)
                .open(db_path.as_ref())
                .unwrap(),
        );
        let address_store = AddressStore::new(env.clone(), logger).unwrap();

        // Test that after inserting to empty, the active account is Some
        {
            let mut db_txn = env.begin_rw_txn().unwrap();
            let (monitor_data, _monitor_id) = get_test_monitor_data_and_id(&mut rng);
            let address_data = AddressData {
                own: true,
                account_key: Some(monitor_data.account_key.clone()),
                subaddress_index: Some(0),
                create_time: 55555,
                comment: "Alice".to_string(),
            };
            address_store
                .insert(
                    &mut db_txn,
                    &monitor_data.account_key.default_subaddress(),
                    &address_data,
                )
                .unwrap();
            assert_eq!(
                address_store
                    .get(&db_txn, &monitor_data.account_key.default_subaddress())
                    .unwrap(),
                address_data
            )
        }

        {}
    }
}
