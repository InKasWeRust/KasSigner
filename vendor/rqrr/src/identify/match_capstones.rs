use alloc::vec::Vec;

use crate::CapStone;

#[derive(Debug, Clone)]
pub struct CapStoneGroup(pub CapStone, pub CapStone, pub CapStone);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Neighbor {
    index: usize,
    distance: f32,
}

/// KASSIGNER: ceiling on each candidate-neighbour list.
/// `find_and_rank_possible_neighbors` ranks every pair from the two lists, so
/// where many capstones look like neighbours the pairs and their sort grow
/// with the product of the lengths; `MAX_CAPSTONES` bounds the capstones,
/// this the product. 32 is far above anything real: a capstone has one
/// horizontal and one vertical neighbour, and on an honest frame those
/// passing the 0.2 gradient test number in single digits.
const MAX_NEIGHBORS: usize = 32;

/// Add a candidate, keeping the `MAX_NEIGHBORS` closest, not the first
/// found: truncating in scan order would drop a real QR's neighbour whenever
/// enough noise came first. A true neighbour is a near one, so it is lost
/// only if `MAX_NEIGHBORS` candidates lie nearer still. A linear scan for
/// the farthest, not a heap: the list is 32 long and this runs once per
/// capstone pair.
fn push_bounded(list: &mut Vec<Neighbor>, cand: Neighbor) {
    if list.len() < MAX_NEIGHBORS {
        list.push(cand);
        return;
    }
    let mut worst = 0usize;
    for (i, n) in list.iter().enumerate() {
        if n.distance > list[worst].distance {
            worst = i;
        }
    }
    if cand.distance < list[worst].distance {
        list[worst] = cand;
    }
}

/// Return each pair Capstone indexes that are likely to be from a QR code
/// Ordered from most symmetric to least symmetric
pub fn find_and_rank_possible_neighbors(capstones: &[CapStone], idx: usize) -> Vec<(usize, usize)> {
    const VIABILITY_THRESHOLD: f32 = 0.25;

    let (hlist, vlist) = find_possible_neighbors(capstones, idx);
    let mut res = Vec::new();
    struct NeighborSet {
        score: f32,
        h_index: usize,
        v_index: usize,
    }
    /* Test each possible grouping */
    for hn in hlist {
        for vn in vlist.iter() {
            let score = {
                if hn.distance < vn.distance {
                    (1.0f32 - hn.distance / vn.distance).abs()
                } else {
                    (1.0f32 - vn.distance / hn.distance).abs()
                }
            };
            if score < VIABILITY_THRESHOLD {
                res.push(NeighborSet {
                    score,
                    h_index: hn.index,
                    v_index: vn.index,
                });
            }
        }
    }

    res.sort_unstable_by(|a, b| {
        (a.score)
            .partial_cmp(&(b.score))
            .expect("Neighbor distance should never cause a div by 0")
    });
    res.iter().map(|n| (n.h_index, n.v_index)).collect()
}

fn find_possible_neighbors(capstones: &[CapStone], idx: usize) -> (Vec<Neighbor>, Vec<Neighbor>) {
    let cap = &capstones[idx];
    let mut hlist = Vec::new();
    let mut vlist = Vec::new();

    /* Look for potential neighbours by examining the relative gradients
     * from this capstone to others.
     */
    #[allow(clippy::needless_range_loop)]
    for others_idx in 0..capstones.len() {
        if others_idx == idx {
            continue;
        }

        let cmp_cap = &capstones[others_idx];

        let (mut u, mut v) = cap.c.unmap(&cmp_cap.center);
        u = (u - 3.5f32).abs();
        v = (v - 3.5f32).abs();

        if u < 0.2f32 * v {
            push_bounded(
                &mut hlist,
                Neighbor {
                    index: others_idx,
                    distance: v,
                },
            );
        }

        if v < 0.2f32 * u {
            push_bounded(
                &mut vlist,
                Neighbor {
                    index: others_idx,
                    distance: u,
                },
            );
        }
    }

    (hlist, vlist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(index: usize, distance: f32) -> Neighbor {
        Neighbor { index, distance }
    }

    #[test]
    fn bounded_list_never_exceeds_the_cap() {
        // Without the bound a list grows with the capstones.
        let mut l = Vec::new();
        for i in 0..10_000 {
            push_bounded(&mut l, n(i, (i % 977) as f32));
        }
        assert_eq!(l.len(), MAX_NEIGHBORS);
    }

    #[test]
    fn bounded_list_keeps_the_closest_not_the_first() {
        // Candidates arrive worst first; the nearest must survive, not the
        // first seen, or the bound costs honest decodes.
        let mut l = Vec::new();
        for i in 0..200usize {
            push_bounded(&mut l, n(i, (200 - i) as f32));
        }
        assert_eq!(l.len(), MAX_NEIGHBORS);
        let mut d: Vec<f32> = l.iter().map(|x| x.distance).collect();
        d.sort_by(|a, b| a.partial_cmp(b).unwrap());
        // Distances ran 200 down to 1, so the kept set must be 1..=32.
        assert_eq!(d.first().copied(), Some(1.0));
        assert_eq!(d.last().copied(), Some(MAX_NEIGHBORS as f32));
    }

    #[test]
    fn a_far_candidate_cannot_evict_a_near_one() {
        let mut l = Vec::new();
        for i in 0..MAX_NEIGHBORS {
            push_bounded(&mut l, n(i, 1.0));
        }
        push_bounded(&mut l, n(9999, 500.0));
        assert_eq!(l.len(), MAX_NEIGHBORS);
        assert!(
            l.iter().all(|x| x.index != 9999),
            "a farther candidate displaced a nearer one"
        );
    }

    #[test]
    fn under_the_cap_nothing_is_dropped() {
        // An honest frame's few candidates are all kept, in order.
        let mut l = Vec::new();
        for i in 0..5usize {
            push_bounded(&mut l, n(i, i as f32));
        }
        assert_eq!(l.len(), 5);
        for (i, e) in l.iter().enumerate() {
            assert_eq!(e.index, i);
        }
    }
}
