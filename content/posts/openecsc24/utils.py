def galois_to_python_mat(A):
    return [[int(x) for x in row] for row in A]

def galois_to_python_vec(v):
    return [int(x) for x in v]

def python_to_galois_mat(FF, A):
    return FF([[int(x) for x in row] for row in A])

def python_to_galois_vec(FF, v):
    return FF([int(x) for x in v])

def python_bytes_to_galois_vec(FF, b):
    if FF.order != 256:
        raise ValueError("python_bytes_to_galois_vec only supports GF(2^8)")
    return FF(list(b))


# These are provided for your convenience, unused by the challenge, requires `from sage.all import matrix, vector`
def sage_to_python_mat(A):
    return [[x.to_integer() for x in row] for row in A]

def sage_to_python_vec(v):
    return [x.to_integer() for x in v]

def python_to_sage_mat(FF, A):
    return matrix(FF, [[FF.from_integer(int(x)) for x in row] for row in A])

def python_to_sage_vec(FF, v):
    return vector(FF, [FF.from_integer(int(x)) for x in v])
