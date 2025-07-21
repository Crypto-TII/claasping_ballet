import json
import time
import sys
import traceback
import datetime

from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables

configurations = [ (128, 128), (128, 256), (256, 256) ]

for num_rounds in range(1, 9):
    for block_size, key_size in configurations:
        filename = (
            f"find_one_xor_differential_trail__ballet_{num_rounds}round_"
            f"{block_size}block_{key_size}key__PARKISSAT_EXTsolver_1thread.json"
        )
        
        start_round = time.perf_counter()

        ballet = BalletBlockCipher(block_bit_size=block_size, key_bit_size=key_size, number_of_rounds=num_rounds)
        ciphertext_id = ballet.get_all_components()[-1].id
        sat_model = SatXorDifferentialModel(ballet)

        impossible_differentials = []

        key_diff = [0 for _ in range(key_size)]
        key_fixed = set_fixed_variables("key", "equal", range(key_size), key_diff)

        for pt_bit in range(block_size):
            for ct_bit in range(block_size):
                pt_diff = [0 for _ in range(block_size)]
                pt_diff[pt_bit] = 1
                pt_fixed = set_fixed_variables("plaintext", "equal", range(block_size), pt_diff)

                ct_diff = [0 for _ in range(block_size)]
                ct_diff[ct_bit] = 1
                ct_fixed = set_fixed_variables(ciphertext_id, "equal", range(block_size), ct_diff)

                fixed_vars = [pt_fixed, ct_fixed, key_fixed]

                start_time = time.perf_counter()
                try:
                    result = sat_model.find_one_xor_differential_trail(
                        fixed_values=fixed_vars,
                        solver_name="PARKISSAT_EXT"
                    )
                    elapsed_time = time.perf_counter() - start_time

                    if result is not None and result.get("status") == "UNSATISFIABLE":
                        impossible_differentials.append({
                            "pt_bit": pt_bit,
                            "ct_bit": ct_bit,
                            "time_seconds": round(elapsed_time, 4)
                        })

                except Exception as e:
                    error_message =  f"args={sys.argv}\nException occurred during SAT ({num_rounds}r {block_size}b {key_size}k ({pt_diff}ptDiff {ct_diff}ctDiff) {pt_bit}pt_bit {ct_bit}ct_bit): {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-" * 60 + f" time={datetime.datetime.now()}\n\n"
                    with open(filename, "w") as f:
                        f.write(error_message)
                    with open("errors.log", "a") as f:
                        f.write(error_message)

        total_time = time.perf_counter() - start_round


        output_data = {
            "block_size": block_size,
            "key_size": key_size,
            "num_rounds": num_rounds,
            "total_time_seconds": round(total_time, 2),
            "impossible_differentials": impossible_differentials
        }

        try:
            with open(filename, "w") as f:
                json.dump(output_data, f, indent=4)
        except Exception as e:
            error_data = f"Exception occurred while saving results ({num_rounds} {block_size} {key_size}): {str(e)}\n" + "-" * 60 + f" end={datetime.datetime.now()}\n\n"
            with open("errors.log", "a") as f:
                f.write(error_data)
