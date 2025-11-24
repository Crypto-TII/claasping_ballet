import time
import sys
from os import remove
import traceback
import datetime
from itertools import combinations
from shutil import copyfileobj
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables

from concurrent.futures import ProcessPoolExecutor

solver = "CRYPTOMINISAT_EXT"

def save(filename,mod,string):
    try:
        with open(filename, mod) as f:
            f.write(string)
    except Exception as e:
        error_data = f"Exception occurred while saving results ({sys.argv}): {str(e)}\n" + "-" * 60 + f" end={datetime.datetime.now()}\n\n"
        with open("errors.log", "a") as f:
            f.write(error_data)

def searchImpossibleDifferentials(pt_combinations,ct_combinations,block_size,key_size,num_rounds,filename):
    #print(f"deb: pt_combinations={pt_combinations}\ndeb: ct_combinations={ct_combinations}")
    ballet = BalletBlockCipher(block_bit_size=block_size, key_bit_size=key_size, number_of_rounds=num_rounds)
    ciphertext_id = ballet.get_all_components()[-1].id
    sat_model = SatXorDifferentialModel(ballet)

    key_diff = [0 for _ in range(key_size)]
    key_fixed = set_fixed_variables("key", "equal", range(key_size), key_diff)

    for pt_bits in pt_combinations:
        for ct_bit in ct_combinations:
            pt_diff = [0] * block_size
            pt_diff[pt_bits] = 1
            pt_fixed = set_fixed_variables("plaintext", "equal", range(block_size), pt_diff)

            ct_diff = [0] * block_size
            ct_diff[ct_bit[0]] = 1
            ct_diff[ct_bit[1]] = 1
            ct_fixed = set_fixed_variables(ciphertext_id, "equal", range(block_size), ct_diff)

            fixed_vars = [pt_fixed, ct_fixed, key_fixed]
            try:
                start_time = time.perf_counter()
                result = sat_model.find_one_xor_differential_trail(
                    fixed_values=fixed_vars,
                    solver_name= solver
                )
                elapsed_time = time.perf_counter() - start_time

                if result is not None and result.get("status") == "UNSATISFIABLE":
                    msg = '\t\t{'+f'"pt_bits": {[pt_bits]}, "ct_bit": {list(ct_bit)}, "time_seconds": {round(elapsed_time, 4)}'+'},\n'
                    save(filename,"a",msg)

            except Exception as e:
                error_message =  f"args={sys.argv}\nException occurred during SAT ({num_rounds}r {block_size}b {key_size}k ({pt_diff}ptDiff {ct_diff}ctDiff) {pt_bits}pt_bits {ct_bit}ct_bit): {repr(e)}\n\n" + f"Traceback:\n{traceback.format_exc()}" + "-" * 60 + f" time={datetime.datetime.now()}\n\n"
                save("errors.log", "a", error_message)
                msg =  f'\t\t"error": "time={datetime.datetime.now()} {pt_bits}pt_bits {ct_bit}ct_bit): {repr(e)}",\n'
                save(filename,"a",msg)
    

def parallel_resolution(filename,num_rounds,block_size, key_size,c):
    pt_combinations = list(range(block_size))
    ct_combinations = list(combinations(range(block_size), 2))
    ct_comb_partial_len = len(ct_combinations) // c


    with ProcessPoolExecutor(max_workers=c) as executor:
        for i in range(c):
            if i != c-1:
                subset_ct_combinations = ct_combinations[ct_comb_partial_len*i:ct_comb_partial_len*(i+1)]
            else:
                subset_ct_combinations = ct_combinations[ct_comb_partial_len*i:]
            new_filename = filename + f"_{i}.tmp"
            save(new_filename,"w","")

            executor.submit(
                searchImpossibleDifferentials,
                pt_combinations,
                subset_ct_combinations,
                block_size,
                key_size,
                num_rounds,
                new_filename
            )
            


c = 100
configurations = [(128, 128), (256, 256), (128, 256)]

for num_rounds in range(7, 9):
    for block_size, key_size in configurations:
        filename = f"new_impossibile_differential_hammingWeightpt1ct2__ballet_{num_rounds}round_{block_size}block_{key_size}key__{solver}solver_{c}thread.json"
        output_data = '{'+f'\n\t"block_size": {block_size},\n\t"key_size": {key_size},\n\t"num_rounds": {num_rounds},\n\t"num_core": {c},'
        save(filename,"w",output_data)

        start_round = time.perf_counter()
        parallel_resolution(filename[:-5],num_rounds,block_size, key_size,c)
        total_time = time.perf_counter() - start_round

        # save result
        output_data = f'\n\t"total_time_seconds": {round(total_time, 2)},\n\t"impossible_differentials": [\n'
        save(filename,"a",output_data)
        # merge all the files results
        with open(filename, "a") as dest:
            for i in range(c):
                with open(filename[:-5] + f"_{i}.tmp", "r") as src:
                    copyfileobj(src, dest)
                remove(filename[:-5] + f"_{i}.tmp")
        save(filename,"a","\t]\n}")
