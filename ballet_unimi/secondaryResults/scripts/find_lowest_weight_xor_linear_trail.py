import sys
import json
import traceback
import datetime
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import (
    SatXorLinearModel)
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list

start_date = datetime.datetime.now()
# read parameters
try:
    solver= str(sys.argv[1])
    if solver not in ["cryptominisat", "picosat", "glucose", "glucose-syrup", "CADICAL_EXT", "CRYPTOMINISAT_EXT","KISSAT_EXT", "PARKISSAT_EXT", "MATHSAT_EXT", "YICES_SAT_EXT"]:
        print("Error. solver selected doesn't exist")
        exit(-1)

    cipher= str(sys.argv[2])
    if cipher not in ["ublock", "ballet"]:
        print("Error. Cipher selected doesn't exist. Chose ublock or ballet")
        exit(-1)

    block_bit = int(sys.argv[3])
    if block_bit != 128 and block_bit != 256:
        print("Error. You are trying to set block_bit_size to a number different from 128 or 256")
        exit(-1)
    
    key_bit = int(sys.argv[4])
    if key_bit != 128 and key_bit != 256:
        print("Error. You are trying to set key_bit_size to a number different from 128 or 256")
        exit(-1)
    
    if block_bit > key_bit:
        print("Error. You cannot set block_bit bigger than key_bit")
        exit(-1)

    round= int(sys.argv[5])
    if round <= 0:
        print("Error. You are trying to set a number of round <= 0")
        exit(-1)
except:
    print("Missing parameters. try to run something like these \n`python3 find_lowest_weight_xor_linear_trail.py CRYPTOMINISAT_EXT ballet 128 256 3`\n`python3 find_lowest_weight_xor_linear_trail.py PARKISSAT_EXT ublock 256 256 2`")
    exit(-1)

# find the trail
if cipher == "ublock":
    ublock = UblockBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
    sat = SatXorLinearModel(ublock)
elif cipher == "ballet":
    ballet = BalletBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
    sat = SatXorLinearModel(ballet)
else:
    print("Unexpected error")
    exit(-1)

fixed_values = []
fixed_values.append(set_fixed_variables('key', 'equal', list(range(key_bit)), integer_to_bit_list(0, key_bit, 'big'))) # rerun without
fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(block_bit)), integer_to_bit_list(0, block_bit, 'big'))) 

try :
    trail = sat.find_lowest_weight_xor_linear_trail(fixed_values, solver_name=solver)
    trail["cipher"] = str(trail["cipher"])
except Exception as e:
    errorMessage = f"args={sys.argv}\nException occurred during SAT: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
    # print(errorMessage)
    with open(f"find_lowest_weight_xor_linear_trail__{cipher}_{block_bit}block_{key_bit}key_{round}rounds__{solver}solver.json","a") as f:
        f.write(errorMessage)
    with open("errors.log","a") as f:
        f.write(errorMessage)
    exit(-1)

# show/save the results
try: 
    # print(f"Done find_lowest_weight_xor_linear_trail__{cipher}_{block_bit}block_{key_bit}key_{round}rounds__{solver}solver\n",json.dumps(trail,indent=4))
    with open(f"find_lowest_weight_xor_linear_trail__{cipher}_{block_bit}block_{key_bit}key_{round}rounds__{solver}solver.json","a") as f:
        f.write(json.dumps(trail,indent=4))
except Exception as e:
    errorMessage = f"args={sys.argv}\nException occurred during result saving: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
    # print(errorMessage)
    with open("errors.log","a") as f:
        f.write(errorMessage)
