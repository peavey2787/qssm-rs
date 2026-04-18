//! ConstraintSystem wrapper that threads [`PolyOpContext`] into XOR hooks.

#![forbid(unsafe_code)]

use super::context::PolyOpContext;
use super::r1cs::{ConstraintSystem, VarId, VarKind};

pub struct PolyOpTracingCs<'a, C: ConstraintSystem> {
    pub inner: &'a mut C,
    pub ctx: &'a mut PolyOpContext,
}

impl<'a, C: ConstraintSystem> PolyOpTracingCs<'a, C> {
    /// Sound copy-refresh: new private wire **`fresh`**, **`enforce_equal(fresh, old)`**, depth **0** for **`fresh`**.
    ///
    /// Records [`CopyRefreshMeta`] with **`kind: "manual"`** for [`PolyOpContext::refresh_metadata`].
    pub fn refresh_boolean_wire_copy(
        &mut self,
        old: VarId,
        label: &str,
        segment: Option<&str>,
    ) -> VarId {
        let fresh = self.allocate_variable(VarKind::Private);
        self.inner.enforce_equal(fresh, old);
        self.ctx.reset_wire_mul_depth_zero(fresh);
        let seg = segment
            .map(|s| s.to_string())
            .or_else(|| Some(self.ctx.segment.clone()));
        self.ctx
            .push_refresh_meta(fresh.0, old.0, label.to_string(), seg, "manual");
        self.ctx.manual_refresh_count = self.ctx.manual_refresh_count.saturating_add(1);
        fresh
    }

    pub(crate) fn refresh_boolean_wire_copy_auto(&mut self, old: VarId, label: &str) -> VarId {
        let fresh = self.allocate_variable(VarKind::Private);
        self.inner.enforce_equal(fresh, old);
        self.ctx.reset_wire_mul_depth_zero(fresh);
        self.ctx.push_refresh_meta(
            fresh.0,
            old.0,
            label.to_string(),
            Some(self.ctx.segment.clone()),
            "auto_xor",
        );
        self.ctx.auto_refresh_count = self.ctx.auto_refresh_count.saturating_add(1);
        fresh
    }
}

impl<C: ConstraintSystem> ConstraintSystem for PolyOpTracingCs<'_, C> {
    fn allocate_variable(&mut self, kind: VarKind) -> VarId {
        self.inner.allocate_variable(kind)
    }

    fn enforce_xor(&mut self, mut x: VarId, mut y: VarId, and_xy: VarId, z: VarId) {
        if self.ctx.auto_refresh_enabled {
            let dx = self.ctx.wire_mul_depth(x);
            let dy = self.ctx.wire_mul_depth(y);
            if dx >= 1 && dy >= 1 {
                let refresh_left = if dx > dy {
                    true
                } else if dy > dx {
                    false
                } else {
                    true
                };
                let label = format!("auto_xor:{}:lhs{}_rhs{}", self.ctx.segment, x.0, y.0);
                if refresh_left {
                    let old_x = x;
                    x = self.refresh_boolean_wire_copy_auto(old_x, &label);
                } else {
                    let old_y = y;
                    y = self.refresh_boolean_wire_copy_auto(old_y, &label);
                }
            }
        }
        if let Err(e) = self
            .ctx
            .register_binary_product(x, y, and_xy, "enforce_xor")
        {
            self.ctx.degree_violation = Some(e);
            return;
        }
        self.inner.enforce_xor(x, y, and_xy, z);
    }

    fn enforce_full_adder(&mut self, a: VarId, b: VarId, cin: VarId, sum: VarId, cout: VarId) {
        self.inner.enforce_full_adder(a, b, cin, sum, cout);
    }

    fn enforce_equal(&mut self, a: VarId, b: VarId) {
        self.inner.enforce_equal(a, b);
    }
}
