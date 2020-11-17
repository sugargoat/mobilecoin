// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for wallet accounts

use crate::error::Error;

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::AccountKey;
use mc_common::logger::{log, Logger};
use prost::Message;
use std::sync::Arc;

// LMDB Database Names
pub const ACCOUNT_DB_NAME: &str = "mobilecoind_db:account_store:account_data";

/// The data associated with an Account.
#[derive(Message, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccountData {
    #[prost(bytes, tag = "1")]
    pub monitor_id: Vec<u8>,

    #[prost(uint64, tag = "2")]
    pub first_subaddress_index: u64,

    #[prost(uint64, tag = "3")]
    pub next_subaddress_index: u64,

    #[prost(uint64, tag = "4")]
    pub change_subaddress: u64,
}

/// Storage for Accounts.
#[derive(Clone)]
pub struct AccountStore {
    /// Environment for LMDB transactions.
    env: Arc<Environment>,

    /// Mapping of address -> Address Data.
    account_data: Database,

    /// Logger.
    logger: Logger,
}

impl AccountStore {
    /// Create a new AccountStore.
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let account_data = env.create_db(Some(ACCOUNT_DB_NAME), DatabaseFlags::empty())?;

        Ok(Self {
            env,
            account_data,
            logger,
        })
    }

    /// Insert or update an Account in the database.
    pub fn insert<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
        data: &AccountData,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        let value_bytes = mc_util_serial::encode(data);
        match db_txn.put(
            self.account_data,
            &account_db_key,
            &value_bytes,
            WriteFlags::empty(),
        ) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::KeyExist) => Ok(()),
            Err(err) => Err(Error::from(err)),
        }?;

        log::trace!(
            self.logger,
            "Inserting {:?} ({:?}) to account store",
            account,
            data,
        );

        Ok(())
    }

    /// Returns the Account Data associated with a given account
    pub fn get(
        &self,
        db_txn: &impl Transaction,
        account: &AccountKey,
    ) -> Result<AccountData, Error> {
        let account_db_key = mc_util_serial::encode(account);
        match db_txn.get(self.account_data, &account_db_key) {
            Ok(value_bytes) => Ok(mc_util_serial::decode(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::AccountNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Update the next subaddress for the account
    pub fn update_next_subaddress<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        match db_txn.get(self.account_data, &account_db_key) {
            Ok(value_bytes) => {
                let mut account_data: AccountData = mc_util_serial::decode(value_bytes)?;
                account_data.next_subaddress_index += 1;
                self.delete(db_txn, account)?; // FIXME: allow overwrite
                self.insert(db_txn, account, &account_data)?;
                Ok(())
            }
            Err(lmdb::Error::NotFound) => Err(Error::AccountNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Delete the data stored for an account
    pub fn delete<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        db_txn.del(self.account_data, &account_db_key, None)?;

        Ok(())
    }

    pub fn list_accounts(&self, db_txn: &impl Transaction) -> Result<Vec<AccountData>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.account_data)?;
        Ok(cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, _value_bytes)| {
                        mc_util_serial::decode(key_bytes)
                            .map_err(|_| Error::KeyDeserializationError)
                    })
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }
}
