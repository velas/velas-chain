use std::ops::Range;

use evm_state::BlockNum;
use rangemap::RangeSet;

use crate::triedb::MAX_JUMP_OVER_ABYSS_GAP;

use super::RangeJSON;

const MAX_CLIENT_WORK_CHUNK: usize = 10_000;

impl RangeJSON {
    fn event_horizon(kickstart_point: BlockNum, max_gap: usize) -> Range<BlockNum> {
        let start = kickstart_point.saturating_sub(max_gap as BlockNum);
        let end = kickstart_point.saturating_add(max_gap as BlockNum + 1);
        start..end
    }

    fn cap<'a>(input: RangeSet<BlockNum>, base: Range<BlockNum>) -> Vec<Range<BlockNum>> {
        let mut left = MAX_CLIENT_WORK_CHUNK as BlockNum;
        let mut result = vec![];
        for element in input.into_iter() {
            let elem_len = if element.is_empty() {
                0
            } else {
                element.end - element.start
            };
            if elem_len > left {
                if element.start < base.start {
                    result.push((element.end - left)..element.end);
                } else {
                    result.push(element.start..(element.start + left));
                }
                break;
            } else {
                result.push(element.clone());
                left -= elem_len;
            }
        }
        result
    }
    fn intersect(a: &Range<BlockNum>, b: &Range<BlockNum>) -> Range<BlockNum> {
        let start = std::cmp::max(a.start, b.start);
        let end = std::cmp::min(a.end, b.end);
        start..end
    }
    fn bound(input: RangeSet<BlockNum>, event_horizon: Range<BlockNum>) -> RangeSet<BlockNum> {
        let bounded = input.overlapping(&event_horizon);
        let mut result = RangeSet::new();
        for range in bounded {
            result.insert(Self::intersect(range, &event_horizon));
        }
        // println!("bounded: {:#?}", result);
        result
    }

    fn diff_internal(
        input: Range<BlockNum>,
        target: std::ops::Range<BlockNum>,
        kickstart_point: BlockNum,
        max_gap: usize,
    ) -> Vec<Range<BlockNum>> {
        let from = RangeSet::from_iter([input.clone()]);

        let difference = RangeSet::from_iter(from.gaps(&target));
        // println!("difference: {:#?}", difference);
        let event_horizon = Self::event_horizon(kickstart_point, max_gap);
        // println!("event_horizon: {:#?}", event_horizon);
        let bounded = Self::bound(difference, event_horizon);
        Self::cap(bounded, input)
    }
    pub fn diff(
        &self,
        target: std::ops::Range<BlockNum>,
        kickstart_point: BlockNum,
    ) -> Vec<Range<BlockNum>> {
        let self_coarse = self.get();
        Self::diff_internal(
            self_coarse,
            target,
            kickstart_point,
            MAX_JUMP_OVER_ABYSS_GAP,
        )
    }
}

#[cfg(test)]
mod tests {
    use evm_state::BlockNum;

    use crate::triedb::range::{diff::MAX_CLIENT_WORK_CHUNK, RangeJSON};
    const TEST_MAX_JUMP_OVER_ABYSS_GAP: usize = 100_000;

    #[test]
    fn test_1() {
        let input = 1_000_000..1_005_000;
        let target = 1..60_000_000;
        let kickstart_point = 1_004_999;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(990000..1000000, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_2() {
        let input = 1_000_000..1_005_000;
        let target = 1..60_000_000;
        let kickstart_point = 1_000_000;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(990000..1000000, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_3() {
        let input = 1..2;
        let target = 1..60_000_000;
        let kickstart_point = 1;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(2..10002, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_4() {
        let input = 1..10002;
        let target = 1..60_000_000;
        let kickstart_point = 10001;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(10002..20002, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_5() {
        let input = 5000..95000;
        let target = 1..60_000_000;
        let kickstart_point = 94999;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(1..5000, result[0]);
        assert_eq!(95000..100001, result[1]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_6() {
        let input = 100000..200000;
        let target = 1..60_000_000;
        let kickstart_point = 100000;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(90000..100000, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_7() {
        let input = 100000..200000;
        let target = 1..60_000_000;
        let kickstart_point = 200000;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(200000..210000, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_8() {
        let input = 1..200000;
        let target = 200000..60_000_000;
        let kickstart_point = 1;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(0, result.len());
        assert_eq!(
            0,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_9() {
        let input = 1..200000;
        let target = 200000..60_000_000;
        let kickstart_point = 199999;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result =
            RangeJSON::diff_internal(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(200000..210000, result[0]);
        assert_eq!(
            MAX_CLIENT_WORK_CHUNK,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }
}
