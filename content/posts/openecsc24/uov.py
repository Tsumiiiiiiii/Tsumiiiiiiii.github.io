import numpy as np
import galois


class UOV:
    def __init__(self, m: int, n: int, field: type[galois.FieldArray]):
        if not (m < n):
            raise ValueError("Require n > m (more total than oil variables)")

        self.m = m
        self.n = n
        self.F = field

        upper_tri = np.triu(np.ones((n, n), dtype=np.uint8))
        oil_oil = np.ones((n, n), dtype=np.uint8)
        oil_oil[:m, :m] = 0  # disallow oil-oil terms
        mask = upper_tri & oil_oil

        # P_i(x) = x^T*Q_i*x + L_i*x + C_i, i = 1,2,...,m
        self.Q = field.Random((m, n, n)) * field(mask)[None, :, :]
        self.L = field.Random((m, n))
        self.C = field.Random(m)

        self.S, self.S_inv = self._random_invertible_matrix(n)

        # used for optimization in signing
        self._tri = np.triu_indices(n)
        self._Qflat = self.Q[:, self._tri[0], self._tri[1]].copy()

        self._L_o = self.L[:, :self.m].copy()  # m * m
        self._L_v = self.L[:, self.m:].copy()  # m * (n-m)
        self._Q_ov = self.Q[:, :self.m, self.m:].copy()  # m * m * (n-m)
        self._Q_vv = self.Q[:, self.m:, self.m:].copy()  # m * (n-m) * (n-m)


    def sign(self, y: galois.FieldArray) -> galois.FieldArray | None:
        if y.size != self.m:
            raise ValueError("message must have length m")

        # take deterministic vinegars
        a = 13
        v = []
        i = 0
        while len(v) < self.n - self.m:
            a = (37*a + int(y[i]) + 202) % 256
            v.append(a)
            i += 1
            if i >= len(y):
                i = 1
        vinegars = self.F(v)

        while True:
            # optimized for quick maths
            A = self._L_o + (self._Q_ov * vinegars[None, None, :]).sum(axis=2)
            vv_outer = vinegars[:, None] * vinegars[None, :]
            quad_vv = (self._Q_vv * vv_outer).sum(axis=2).sum(axis=1)
            b = y - self.C - (self._L_v @ vinegars) - quad_vv

            # attempt to solve A*o = b
            try:
                oils = np.linalg.solve(A, b)
            except np.linalg.LinAlgError:
                return None  # just give up at this point

            return self.S_inv @ np.concatenate((oils, vinegars))

    def verify(self, y: galois.FieldArray, s: galois.FieldArray) -> bool:
        if y.size != self.m or s.size != self.n:
            return False
        return np.array_equal(self._evaluate_P(self.S @ s), y)

    def _evaluate_P(self, x: galois.FieldArray) -> galois.FieldArray:
        phi = x[self._tri[0]] * x[self._tri[1]]
        quad = self._Qflat @ phi
        return self.C + (self.L @ x) + quad
        # alternative (but slower):
        # return self.F([x.T @ Qi @ x + Li @ x + Ci  for Qi, Li, Ci in zip(self.Q, self.L, self.C)])

    def _random_invertible_matrix(self, dim: int) -> tuple[galois.FieldArray, galois.FieldArray]:
        while True:
            S = self.F.Random((dim, dim))
            if np.linalg.det(S) == 0:
                continue
            S_inv = np.linalg.inv(S)
            return S, S_inv

    def public_key(self):
        Q_pub = self.F([self.S.T @ Q_i @ self.S for Q_i in self.Q])
        L_pub = self.L @ self.S
        C_pub = self.C.copy()
        return Q_pub, L_pub, C_pub

    def public_map(self, x: galois.FieldArray) -> galois.FieldArray:
        # P(S(x))
        if x.size != self.n:
            raise ValueError("s must have length n")
        return self._evaluate_P(self.S @ x)
