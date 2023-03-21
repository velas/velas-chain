use evm_state::BlockNum;

use crate::triedb::EvmHeightIndex;

use super::Client;

const MAX_JUMP_OVER_ABYSS_GAP: BlockNum = 1_000_000;

impl<S> Client<S> 
where S: EvmHeightIndex {
    pub async fn routine(&self) {
        todo!("formulate the whole syncing a single server logic");
        
    }
    
}
