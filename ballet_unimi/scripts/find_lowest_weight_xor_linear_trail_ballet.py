import json
import traceback
import datetime
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher

solver= "PARKISSAT_EXT"

for round in range(1, 11): #choose your arrival round
    for block_bit, key_bit in [(128,128), (128,256), (256,256)]:
        # find the trail
        start_date = datetime.datetime.now()
        ballet = BalletBlockCipher(block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=round)
        sat = SatXorLinearModel(ballet)

        try :
            trail = sat.find_lowest_weight_xor_linear_trail(solver_name=solver)
            trail["cipher"] = str(trail["cipher"])
        except Exception as e:
            errorMessage = f"Error in find_lowest_weight_xor_linear_trail__ballet {round}rounds_{block_bit}block_{key_bit}key\nException occurred during SAT: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
            with open(f"find_lowest_weight_xor_linear_trail__ballet_{round}rounds_{block_bit}block_{key_bit}key__PARKISSAT_EXTsolver_10thread.json","a") as f:
                f.write(errorMessage)
            with open("errors.log","a") as f:
                f.write(errorMessage)
            break

        # save the results
        try: 
            with open(f"find_lowest_weight_xor_linear_trail__ballet_{round}rounds_{block_bit}block_{key_bit}key__PARKISSAT_EXTsolver_10thread.json","w") as f:
                f.write(json.dumps(trail,indent=4))
        except Exception as e:
            errorMessage = f"Error in find_lowest_weight_xor_linear_trail__ballet {round}rounds_{block_bit}block_{key_bit}key\nException occurred during result saving: {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-"*60 + f" start={start_date} end={datetime.datetime.now()}\n\n"
            with open("errors.log","a") as f:
                f.write(errorMessage)
