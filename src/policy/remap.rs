use crate::dns::wire::TYPE_AAAA;

use super::{ParsedQuery, classify};

#[must_use]
pub(crate) fn blocks_aaaa(query: &ParsedQuery, region: &crate::config::RegionConfig) -> bool {
    query.question.qtype == TYPE_AAAA && classify::is_remap_domain(&query.question.name, region)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Question;
    use crate::dns::wire::CLASS_IN;

    #[test]
    fn only_blocks_remapped_ipv6_queries() {
        let Some(region) = crate::config::REGION_CONFIG.first() else {
            return;
        };
        let query = ParsedQuery {
            id: 1,
            flags: 0x0100,
            question: Question {
                name: "x.com".to_owned(),
                qtype: TYPE_AAAA,
                qclass: CLASS_IN,
            },
            client_sent_ecs: false,
            edns: None,
        };
        assert!(blocks_aaaa(&query, region));
    }
}
