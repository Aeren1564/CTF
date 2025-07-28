from plonk import permute_idices
import numpy as np
from ssbls12 import Fp

# Can you do my PoW finding a number with 'proof_bits' 0?
proof_bits = 60

P = 141528306768650330822240853633706129757483856122032705239787104121712635648968054105923247863678392515560924452725039847310690005346202502323120546096317520792028956290235540662469845864261110405157081321203178742884080504319649527761728762230759915456400855499594340877712636427414085441127049782858937718299

def gen_circuit(n, msg, g, g_values):
    """
    PoW circuit (maybe?): g^x = h (mod P), and h = 0 (mod 2^proof_bits)
    public input: msg + g

    x_values: x in binary
    """
    
    # Initialize wire and witness dictionaries
    wires = {
        'left': [],
        'right': [],
        'output': []
    }
    vars = {}
    
    # Gates
    add = np.array([1, 1, 0, -1, 0])
    sub = np.array([1, -1, 0, -1, 0])
    mul = np.array([0, 0, 1, -1, 0])
    const5 = np.array([0, 1, 0, 0, -5])
    public_input = np.array([0, 1, 0, 0, 0])
    empty = np.array([0, 0, 0, 0, 0])

    gates_matrix = []
    # TODO CTF: check float witness

    # Public input
    for c in msg:
        wires['left'].append('1')
        wires['right'].append(str(c))
        wires['output'].append(str(c))
        gates_matrix.append(public_input)
     
    var_idx = 0

    # x values
    # for i in range(n + 1):
    #     vars[i] = x_values[i]
    var_idx += n + 1

    # x values are binary
    for i in range(n + 1):
        wires['left'].append(f'var{i}')
        wires['right'].append('-1')
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = x_values[i] - 1
        gates_matrix.append(add)
        var_idx += 1
        wires['left'].append(f'var{var_idx - 1}')
        wires['right'].append(f'var{i}')
        wires['output'].append('0')
        gates_matrix.append(mul)

    # Calculate v_i = x_i * g_i + 1 - x_i = x_i*(g_i - 1) + 1
    v_wires = []
    for i in range(n + 1):
        # Multiplication gate: x_i * (g_i - 1)
        wires['left'].append(f'var{i}')
        wires['right'].append(str(g_values[i] - 1))  # Constant multiplication
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = x_values[i] * (g_values[i] - 1)
        gates_matrix.append(mul)
        temp_wire = var_idx
        var_idx += 1
        
        # Addition gate: + 1
        wires['left'].append(f'var{temp_wire}')
        wires['right'].append('1')  # Constant addition
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = vars[temp_wire] + 1
        gates_matrix.append(add)
        v_wires.append(var_idx)
        var_idx += 1
    
    # Now create multiplication tree to compute product of all v_i
    current_product_wires = v_wires.copy()
    
    while len(current_product_wires) > 1:
        new_product_wires = []
        for i in range(0, len(current_product_wires), 2):
            if i + 1 < len(current_product_wires):
                # Multiply two elements
                wires['left'].append(f'var{current_product_wires[i]}')
                wires['right'].append(f'var{current_product_wires[i+1]}')
                wires['output'].append(f'var{var_idx}')
                # vars[var_idx] = vars[current_product_wires[i]] * vars[current_product_wires[i+1]]
                gates_matrix.append(mul)
                new_product_wires.append(var_idx)
                var_idx += 1
            else:
                # Odd number of elements, carry forward the last one
                new_product_wires.append(current_product_wires[i])
        current_product_wires = new_product_wires

    # k*N
    wires['left'].append(f'var{var_idx}')
    # vars[var_idx] = k
    var_idx += 1
    wires['right'].append(str(P))
    wires['output'].append(f'var{var_idx}')
    # vars[var_idx] = k*P
    gates_matrix.append(mul)
    var_idx += 1

    # h  = Final product - k*p
    final_product_wire = current_product_wires[0]
    wires['left'].append(f'var{final_product_wire}')
    wires['right'].append(f'var{var_idx - 1}') 
    wires['output'].append(str(f'var{var_idx}'))
    # vars[var_idx] = vars[final_product_wire] - vars[var_idx - 1]
    gates_matrix.append(sub)
    var_h = var_idx
    var_idx += 1

    # k2 * 2^(proof_bits)
    wires['left'].append(f'var{var_idx}')
    wires['right'].append(str(2**proof_bits)) 
    # vars[var_idx] = k2
    var_idx += 1
    wires['output'].append(f'var{var_idx}')
    # vars[var_idx] = k2 * (2**proof_bits)
    gates_matrix.append(mul)
    var_idx += 1 

    # h - k2 * 2^(proof_bits) == 0
    wires['left'].append(f'var{var_h}')  # h
    wires['right'].append(f'var{var_idx - 1}')
    wires['output'].append('0')
    gates_matrix.append(sub)

    # vars[var_idx] = vars[final_product_wire] - vars[var_idx - 1]
    # var_idx += 1
    # IF ABOVE TODO CTF: h < p


    empty_idx = 0
    while (len(gates_matrix) & len(gates_matrix) - 1) != 0: # number of gates must be power of 2
        wires['left'].append(f'empty{empty_idx}')
        wires['right'].append(f'empty{empty_idx + 1}')
        wires['output'].append(f'empty{empty_idx + 2}')
        # for i in range(3):
        #     vars[var_idx + empty_idx + i] = 0
        gates_matrix.append(empty)
        empty_idx += 3  

    assert len(wires['left']) == len(wires['right']) == len(wires['output']) == len(gates_matrix)
    gates_matrix = np.array(gates_matrix).transpose()

    # print(vars[final_product_wire], vars[var_h], vars[var_h] % 2**proof_bits)
    return {
        'wires': wires,
        'gates': gates_matrix   
    }

# gen PoW
def preprocess(msg):
    # Example usage:
    msg = list(msg) # convert from bytes
    n = proof_bits + 7  # For x_0, x_1, ..., x_n. Not len(gates_matrix[0])
    g = sum(msg) % P
    assert g % 2 == 1
    g_values = [pow(g, 2**i, P) for i in range(n + 1)] 
    # x_values = [1, 0, 1, 1, 0, 1] + [0]*(n + 1 - 6)  # Example x values (binary)

    circuit = gen_circuit(n, msg, g, g_values)

    wires = circuit['wires']['left'] + circuit['wires']['right'] + circuit['wires']['output']

    permutation = permute_idices(wires)

    return wires, permutation, circuit['gates']

if __name__ == "__main__":
    preprocess(b'111')