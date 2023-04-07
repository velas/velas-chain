use std::ops::Range;

use evm_state::BlockNum;
use rangemap::RangeSet;

use super::RangeJSON;

impl RangeJSON {
    fn event_horizon(kickstart_point: BlockNum, max_gap: usize) -> Range<BlockNum> {
        let start = kickstart_point.saturating_sub(max_gap as BlockNum);
        let end = kickstart_point.saturating_add(max_gap as BlockNum + 1);
        start..end
    }

    fn filter_right(input: RangeSet<BlockNum>, base: Range<BlockNum>) -> Vec<Range<BlockNum>> {
        let mut result = vec![];
        for element in input.into_iter() {
            if element.start < base.start {
                // forbidding backwards ranges for now
                continue;
            } else {
                result.push(element);
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

    pub fn diff(
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
        Self::filter_right(bounded, input)
    }
}

#[cfg(test)]
mod tests {
    use evm_state::BlockNum;

    use crate::triedb::range::RangeJSON;
    const TEST_MAX_JUMP_OVER_ABYSS_GAP: usize = 100_000;

    const TEST_LARGE_MAX_JUMP_OVER_ABYSS_GAP: usize = 700_000;

    #[test]
    fn test_1() {
        let input = 1_000_000..1_005_000;
        let target = 1..60_000_000;
        let kickstart_point = 1_004_999;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(1005000..1105000, result[0]);
        assert_eq!(
            100000,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(1005000..1100001, result[0]);
        assert_eq!(
            95001,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(2..100002, result[0]);
        assert_eq!(
            100_000,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(10002..110002, result[0]);
        assert_eq!(
            100_000,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(95000..195000, result[0]);
        assert_eq!(
            100_000,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(200000..200001, result[0]);
        assert_eq!(
            1,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(200000..300001, result[0]);
        assert_eq!(
            100_001,
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
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
        let result = RangeJSON::diff(input, target, kickstart_point, TEST_MAX_JUMP_OVER_ABYSS_GAP);
        println!("{:#?}", result);

        assert_eq!(200000..300000, result[0]);
        assert_eq!(
            100_000,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }

    #[test]
    fn test_10() {
        let input = 1..200000;
        let target = 200000..60_000_000;
        let kickstart_point = 199999;
        println!("{:?} -> {:?} {:?}", input, target, kickstart_point);
        let result = RangeJSON::diff(
            input,
            target,
            kickstart_point,
            TEST_LARGE_MAX_JUMP_OVER_ABYSS_GAP,
        );
        println!("{:#?}", result);

        assert_eq!(200000..900000, result[0]);
        assert_eq!(
            TEST_LARGE_MAX_JUMP_OVER_ABYSS_GAP,
            result
                .clone()
                .into_iter()
                .flatten()
                .collect::<Vec<BlockNum>>()
                .len()
        );
    }
}
