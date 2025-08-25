import sys
import json
import traceback
import datetime
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list

solver = "PARKISSAT_EXT" # use 100 core

# 7 round trail used as a possible starting point for the search
intermediate_outputs_7round = {
    "intermediate_output_0_9":  "0x00000000000000000000000000000000",
    "intermediate_output_0_10": "0x00440000000800000000800000044002",
    "intermediate_output_1_9":  "0x00000000000000000000000000000000",
    "intermediate_output_1_10": "0x00080000000000000001000000008000",
    "intermediate_output_2_9":  "0x00000000000000000000000000000000",
    "intermediate_output_2_10": "0x00000000000000000000000000010000",
    "intermediate_output_3_9":  "0x00000000000000000000000000000000",
    "intermediate_output_3_10": "0x00000000000000008000000000000000",
    "intermediate_output_4_9":  "0x00000000000000000000000000000000",
    "intermediate_output_4_10": "0x00000000000001000000200080000000",
    "intermediate_output_5_9":  "0x00000000000000000000000000000000",
    "intermediate_output_5_10": "0x00000100004200000840400000002000",
    "intermediate_output_6_9":  "0x00000000000000000000000000000000"
}
# 8 round trail used as a possible starting point for the search
intermediate_outputs_8round = {
    "intermediate_output_0_9":  "0x00000000000000000000000000000000",
    "intermediate_output_0_10": "0x02022010004400000004400200202000",
    "intermediate_output_1_9":  "0x00000000000000000000000000000000",
    "intermediate_output_1_10": "0x00440000000800000000800000044002",
    "intermediate_output_2_9":  "0x00000000000000000000000000000000",
    "intermediate_output_2_10": "0x00080000000000000001000000008000",
    "intermediate_output_3_9":  "0x00000000000000000000000000000000",
    "intermediate_output_3_10": "0x00000000000000000000000000010000",
    "intermediate_output_4_9":  "0x00000000000000000000000000000000",
    "intermediate_output_4_10": "0x00000000000000008000000000000000",
    "intermediate_output_5_9":  "0x00000000000000000000000000000000",
    "intermediate_output_5_10": "0x00000000000001000000200080000000",
    "intermediate_output_6_9":  "0x00000000000000000000000000000000",
    "intermediate_output_6_10": "0x00000100004200000840400000002000",
    "intermediate_output_7_9":  "0x00000000000000000000000000000000"
}
# 9 round trail used as a possible starting point for the search
intermediate_outputs_9round = {
    'intermediate_output_0_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_0_10': '0x00000100000000000000000080040000',
    'intermediate_output_1_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_1_10': '0x00000000000040000000400e00000000',
    'intermediate_output_2_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_2_10': '0x0000400000000400000080000000400e', 
    'intermediate_output_3_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_3_10': '0x00000400010800000109000000008000',
    'intermediate_output_4_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_4_10': '0x01080000020100000000000001090000', 
    'intermediate_output_5_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_5_10': '0x02010000400000044000000400000000', 
    'intermediate_output_6_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_6_10': '0x40000004804000000000000040000004', 
    'intermediate_output_7_9':  '0x00000000000000000000000000000000', 
    'intermediate_output_7_10': '0x80400000800000100002001000000000', 
    'intermediate_output_8_9':  '0x00000000000000000000000000000000'
}
block_bit, key_bit = (128,128)
intermediate_outputs = intermediate_outputs_7round



def hex_to_bitlist(hex_str):
    val_int = int(hex_str, 16)
    bit_len = (len(hex_str) - 2) * 4
    return integer_to_bit_list(val_int, bit_len, "big")

for round in range(8, 16): 
    filename= f"find_lowest_weight_xor_differential_trail_starting_from_given_trail__ballet_{block_bit}block_{key_bit}key_{round}rounds7fixed__{solver}solver__50thread.json"
    start_date = datetime.datetime.now()

    ballet = BalletBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
    sat = SatXorDifferentialModel(ballet)

    fixed_values = []
    fixed_values.append(set_fixed_variables('key', 'equal', list(range(key_bit)), integer_to_bit_list(0, key_bit, 'big')))
    fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(block_bit)), integer_to_bit_list(0, block_bit, 'big')))

    for var_name, hex_val in intermediate_outputs.items():
        bits = hex_to_bitlist(hex_val)
        bit_indices = list(range(len(bits)))
        fixed_values.append(set_fixed_variables(var_name, 'equal', bit_indices, bits))

    try:
        trail = sat.find_lowest_weight_xor_differential_trail(fixed_values, solver_name=solver)
        trail["cipher"] = str(trail["cipher"])
    except Exception as e:
        errorMessage = f"args={sys.argv}\nException occurred during SAT: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
        with open(filename,"a") as f:
            f.write(errorMessage)
        with open("errors.log","a") as f:
            f.write(errorMessage)
        break

    try: 
        with open(filename,"a") as f:
            f.write(json.dumps(trail, indent=4))
    except Exception as e:
        errorMessage = f"args={sys.argv}\nException occurred during result saving: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
        with open("errors.log","a") as f:
            f.write(errorMessage)
