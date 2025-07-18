import sys
import json
import traceback
import datetime
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def search_impossible_xor_differential_trail(round, block_bit, key_bit, cipher, solver):
    start_date = datetime.datetime.now()

    if cipher == "ublock":
        primitive = UblockBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
        cp = MznImpossibleXorDifferentialModel(primitive)
    elif cipher == "ballet":
        primitive = BalletBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
        cp = MznImpossibleXorDifferentialModel(primitive)
    else:
        with open("errors.log","a") as f:
            f.write(f"args={sys.argv}\nWrong selected cipher (cipher={cipher})\n\n")
        return


    fixed_values = []
    fixed_values.append(set_fixed_variables('key', 'equal', list(range(key_bit)), integer_to_bit_list(0, key_bit, 'little')))
    fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(block_bit)), integer_to_bit_list(0, block_bit, 'little')))
    fixed_values.append(set_fixed_variables(f'inverse_{primitive.get_all_components_ids()[-1]}', 'not_equal', range(block_bit), integer_to_bit_list(0, block_bit, 'little')))

    try:
        trail = cp.find_one_impossible_xor_differential_trail(round, fixed_values, solver_name= solver, middle_round= int(round/2), final_round= round, intermediate_components= False, num_of_processors= 4) 
        trail["cipher"] = str(trail["cipher"])
    except Exception as e:
        errorMessage = f"args={sys.argv} ({cipher}_{round}rounds_{block_bit}block_{key_bit}key__{solver}solver)\nException occurred during CP: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
        with open(f"find_one_impossible_xor_differential_trail__{cipher}_{round}rounds_{block_bit}block_{key_bit}key__{solver}solver.json","w") as f:
            f.write(errorMessage)
        with open("errors.log","a") as f:
            f.write(errorMessage)
        return

    # show/save the results
    try: 
        with open(f"find_one_impossible_xor_differential_trail__{cipher}_{round}rounds_{block_bit}block_{key_bit}key__{solver}solver.json","w") as f:
            f.write(json.dumps(trail,indent=4))
    except Exception as e:
        errorMessage = f"args={sys.argv} ({cipher}_{round}rounds_{block_bit}block_{key_bit}key__{solver}solver)\nException occurred during result saving: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
        with open("errors.log","a") as f:
            f.write(errorMessage)

# parameters
solver = 'Chuffed'
cipher = 'ballet'

# find the trail
for round in range(2,8+1):
    for block_bit, key_bit in [(128,128), (128,256), (256,256)]:
        search_impossible_xor_differential_trail(round, block_bit, key_bit, cipher, solver)

