import time
import sys
import traceback
import datetime
# note: you must manually add the new method (./newLibraryMethods/find_one_lower_differential_trail.py) inside the library to run this file
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher

solver= "CRYPTOMINISAT_EXT"
core = 50

ballet_chipers = [(BalletBlockCipher(number_of_rounds=i), i) for i in [15]] # max 7+1

listOfListOfCipher = [ballet_chipers] 

minutes = 60*36
for ciphers, name in zip(listOfListOfCipher,["ballet128"]):
    for cipher, rounds in ciphers:
        start_date = datetime.datetime.now()
        sat = SatXorDifferentialModel(cipher)

        beg1 = time.time()
        try: 
            result, test_message = sat.find_one_lower_weight_xor_differential_trail_having_max_waist_time_bounded(minutes=minutes, start=123, solver_name=solver)
        except Exception as e:
            errorMessage = f"args={sys.argv}\nException occurred during SAT: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
            with open("errors.log","a") as f:
                f.write(errorMessage)
            break
        end1 = time.time()
        if result is None:
            weight_new = ""
        elif result['status'] == 'UNSATISFIABLE':
            weight_new = "+128"
        else:
            weight_new = int(result['total_weight'])
            is_optimal = result["is_certainly_optimal"]
            
        try: 
            s = f"{cipher.family_name}, {round(end1-beg1,2)}" + f", {rounds}, {weight_new}, {is_optimal}\n" if weight_new not in ["", "+128"] else "\n"
            with open(f"risFindLower_{minutes}min_{core}core.csv","a") as f:
                f.write(s)
            with open(f"search_and_wasted_times_{minutes}min_{core}core.csv", "a") as f:
                f.write(f"{cipher.family_name}, {rounds}, {round(end1-beg1,2)}, " + test_message)
            with open(f"find_one_lower_weight_xor_differential_trail__{name}_{rounds}rounds_{minutes}minutes_{core}core__{weight_new}weight__{solver}solver.txt","w") as g:
                g.write(str(result))
        except Exception as e:
            errorMessage = f"args={sys.argv}\nException occurred during result saving: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
            with open("errors.log","a") as f:
                f.write(errorMessage)
