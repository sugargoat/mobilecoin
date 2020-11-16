// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for wallet addresses
//! * Contains both "owned" and "not owned" addresses, providing some address book-type storage
//! * All owned addresses are public addresses associated with a subaddress for an account
//! * All not-owned addresses are public addresses for intended recipients or expected senders

use crate::error::Error;

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use prost::Message;
use std::sync::Arc;

// LMDB Database Names
pub const ADDRESS_DB_NAME: &str = "mobilecoind_db:address_store:address_data";

/// The Address Data associated with a Public Address in the Address Store.
#[derive(Message, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AddressData {
    /// Whether this address is owned by this wallet
    #[prost(bool, tag = "1")]
    pub own: bool,

    /// If owned, the account_key associated with this address
    #[prost(message, tag = "2")]
    pub account_key: Option<AccountKey>,

    /// The subaddress assigned to this PublicAddress
    /// Not required in the case of this address is for an intended recipient, but is not
    /// associated with an expected sender.
    #[prost(message, tag = "3")]
    pub subaddress_index: Option<u64>,

    /// The time at which this address was added to the wallet.
    /// In seconds since UNIX_EPOCH.
    #[prost(uint64, tag = "4")]
    pub create_time: u64,

    /// Comment associated with this public address.
    #[prost(string, tag = "6")]
    pub comment: String,
}

/// Storage for Addresses.
#[derive(Clone)]
pub struct AddressStore {
    /// Environment for LMDB transactions.
    env: Arc<Environment>,

    /// Mapping of address -> Address Data.
    address_data: Database,

    /// Logger.
    logger: Logger,
}

impl AddressStore {
    /// Create a new AddressStore.
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let address_data = env.create_db(Some(ADDRESS_DB_NAME), DatabaseFlags::empty())?;
        Ok(Self {
            env,
            address_data,
            logger,
        })
    }

    /// Insert a new Address into the database.
    /// Allows overwriting for updates. FIXME: make sure this is tested
    pub fn insert<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        address: &PublicAddress,
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
