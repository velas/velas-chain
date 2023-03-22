use crate::triedb::EvmHeightIndex;

use super::Client;


impl<S> Client<S> 
where S: EvmHeightIndex {
    pub async fn routine(&self) {
        todo!("formulate the whole syncing a single server logic");
        
    }
    
}
