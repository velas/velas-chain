use evm_state::empty_trie_hash;
use tonic::Code;

use crate::triedb::error::{client, client::range_sync::stages::one, evm_height, lock, server};

#[test]
fn test_from_with_metadata_diff_request() {
    {
        let err = server::Error::HashMismatch {
            height: 10,
            expected: empty_trie_hash(),
            actual: empty_trie_hash(),
        };

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(
                one::request::network::FastError::HashMismatch { .. }
            )
        );
    }
    // #### fence
    {
        let err = server::proto::Error::ExceedBlocksMaxGap {
            from: 1,
            to: 70000000,
        };

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(
                one::request::network::FastError::ExceedDiffMaxGap { .. }
            )
        );
    } // #### fence
    {
        let random_status =
            tonic::Status::new(Code::FailedPrecondition, "undecipherable gibberish");
        let random_status_result = random_status.into();
        assert_matches!(
            random_status_result,
            one::request::network::Error::Fast(one::request::network::FastError::Unknown(..))
        );
    }
    // #### fence
    {
        let bt_err = solana_storage_bigtable::Error::BlockNotFound(70000000);
        let evm_height = Into::<evm_height::Error>::into(bt_err);
        let err = Into::<server::Error>::into(evm_height);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(
                one::request::network::FastError::BlockNotFound { .. }
            )
        );
    } // #### fence
      // #### fence
    {
        let evm_height = evm_height::Error::ForbidZero;
        let err = Into::<server::Error>::into(evm_height);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(one::request::network::FastError::ZeroHeight { .. })
        );
    } // #### fence
      // #### fence
    {
        let empty = server::proto::Error::HashEmpty;
        let err = Into::<server::Error>::into(empty);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(one::request::network::FastError::EmptyHash { .. })
        );
    } // #### fence

    {
        let parse = server::proto::Error::HashParse("gibberish".to_owned());
        let err = Into::<server::Error>::into(parse);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(one::request::network::FastError::ParseHash { .. })
        );
    } // #### fence

    {
        let lock = lock::Error::NotFoundTop(empty_trie_hash());
        let err = Into::<server::Error>::into(lock);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(one::request::network::FastError::LockRoot { .. })
        );
    } // #### fence

    {
        let lock = lock::Error::NotFoundNested {
            from: empty_trie_hash(),
            to: empty_trie_hash(),
            description: "giggsdfsfl".to_owned(),
        };
        let err = Into::<server::Error>::into(lock);

        let status: tonic::Status = err.into();

        let result: one::request::network::Error = status.into();

        assert_matches!(
            result,
            one::request::network::Error::Fast(one::request::network::FastError::TreeBroken { .. })
        );
    } // #### fence
}

#[test]
fn test_from_with_metadata_get_nodes() {
    {
        let empty = server::proto::Error::ExceedNodesMaxChunk {
            actual: 100,
            max: 50,
        };
        let err = Into::<server::Error>::into(empty);

        let status: tonic::Status = err.into();

        let result: client::bootstrap::fetch_nodes::get::Error = status.into();

        assert_matches!(
            result,
            client::bootstrap::fetch_nodes::get::Error::Fast(
                client::bootstrap::fetch_nodes::get::FastError::ExceedMaxChunk { .. }
            )
        );
    }

    {
        let empty = server::proto::Error::HashParse("gibberish".to_string());
        let err = Into::<server::Error>::into(empty);

        let status: tonic::Status = err.into();

        let result: client::bootstrap::fetch_nodes::get::Error = status.into();

        assert_matches!(
            result,
            client::bootstrap::fetch_nodes::get::Error::Fast(
                client::bootstrap::fetch_nodes::get::FastError::ParseHash { .. }
            )
        );
    }

    {
        let err = lock::Error::NotFoundTop(empty_trie_hash());

        let status: tonic::Status = err.into();

        let result: client::bootstrap::fetch_nodes::get::Error = status.into();

        assert_matches!(
            result,
            client::bootstrap::fetch_nodes::get::Error::Fast(
                client::bootstrap::fetch_nodes::get::FastError::NotFound { .. }
            )
        );
    }
}
// #### fence
