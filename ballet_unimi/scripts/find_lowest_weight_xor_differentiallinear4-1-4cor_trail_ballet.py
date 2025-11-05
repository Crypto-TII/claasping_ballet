import sys
import json
import traceback
import datetime
import itertools
import math

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel

from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.utils import differential_linear_checker_for_block_cipher_single_key
solver = "PARKISSAT_EXT"
number_of_rounds = 9

for block_bit, key_bit in [(128, 128), (128, 256), (256, 256)]:
    start_date = datetime.datetime.now()
    ballet = BalletBlockCipher(
        block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=9
    )

    middle_part_components = []
    bottom_part_components = []

    for round_number in range(4, 5):
        middle_part_components.append(ballet.get_components_in_round(round_number))

    for round_number in range(5, 9):
        bottom_part_components.append(ballet.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="not_equal",
        bit_positions=range(block_bit),
        bit_values=(0,) * block_bit,
    )

    key = set_fixed_variables(
        component_id="key",
        constraint_type="equal",
        bit_positions=range(key_bit),
        bit_values=(0,) * key_bit,
    )

    ciphertext_difference = set_fixed_variables(
        component_id=f"cipher_output_{number_of_rounds - 1}_10",
        constraint_type="not_equal",
        bit_positions=range(block_bit),
        bit_values=(0,) * block_bit,
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat = SatDifferentialLinearModel(
        ballet,
        component_model_list,
    )


    trail = sat.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=[key, plaintext, ciphertext_difference],
        solver_name=solver,
        num_unknown_vars=block_bit-1,
    )
    trail["cipher"] = str(trail["cipher"])
   
    input_difference_str = trail['components_values']['plaintext']['value']
    output_mask_str = trail['components_values']['cipher_output_8_10']['value']
    key_str = trail['components_values']['key']['value']

    input_difference = int(input_difference_str, 16)
    output_mask =int(output_mask_str, 16)
    key=int(key_str, 16)
    number_of_samples = 2 ** 18
    number_of_rounds = 9
   
    corr = differential_linear_checker_for_block_cipher_single_key(
        ballet, input_difference, output_mask, number_of_samples, block_bit, key_bit, key
    )

    abs_corr = abs(corr)
    print("Correlation:", abs(math.log(abs_corr, 2)))


    with open(
        f"find_lowest_weight_xor_differentiallinear_trail__ballet_{block_bit}block_{key_bit}key_9 rounds 4-1-4__{solver}solver.txt",
        "a",
    ) as f:
        f.write(json.dumps(trail, indent=4))


