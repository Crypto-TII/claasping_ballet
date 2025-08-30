import sys
import json
import traceback
import datetime
import itertools

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list

solver = "PARKISSAT_EXT"
for number_of_rounds in range(9,12):
        
    for block_bit, key_bit in [(128, 128), (128, 256), (256, 256)]:
        start_date = datetime.datetime.now()
        ballet = BalletBlockCipher(
            block_bit_size=block_bit,
            key_bit_size=key_bit,
            number_of_rounds=number_of_rounds
        )

        middle_part_components = []
        bottom_part_components = []

        for round_number in range(2, 3):
            middle_part_components.append(ballet.get_components_in_round(round_number))

        for round_number in range(3, number_of_rounds):
            bottom_part_components.append(ballet.get_components_in_round(round_number))

        middle_part_components = list(itertools.chain(*middle_part_components))
        bottom_part_components = list(itertools.chain(*bottom_part_components))

        middle_part_components = [component.id for component in middle_part_components]
        bottom_part_components = [component.id for component in bottom_part_components]

        plaintext = set_fixed_variables(
            component_id='plaintext',
            constraint_type='not_equal',
            bit_positions=range(block_bit),
            bit_values=(0,) * block_bit
        )

        key = set_fixed_variables(
            component_id='key',
            constraint_type='equal',
            bit_positions=range(key_bit),
            bit_values=(0,) * key_bit
        )


        ciphertext_difference = set_fixed_variables(
            component_id=f'cipher_output_{number_of_rounds-1}_10',
            constraint_type='not_equal',
            bit_positions=range(block_bit),
            bit_values=(0,) * block_bit
        )

        component_model_list = {
            'middle_part_components': middle_part_components,
            'bottom_part_components': bottom_part_components
        }

        sat = SatDifferentialLinearModel(
            ballet,
            component_model_list,
        )

        try:
            trail = sat.find_lowest_weight_xor_differential_linear_trail(
    fixed_values=[key, plaintext, ciphertext_difference],            solver_name=solver,   
                num_unknown_vars=1
            )
            trail["cipher"] = str(trail["cipher"])
        except Exception as e:
            errorMessage = (
                f"args={sys.argv}\n"
                f"Exception occurred during SAT: {repr(e)}\n\n"
                f"Traceback:\n{traceback.format_exc()}"
                + "-" * 60 +
                f" start={start_date} end={datetime.datetime.now()}\n\n"
            )
            with open(
                f"find_lowest_weight_xor_differentiallinear_trail__ballet_{block_bit}block_{key_bit}key_9rounds__{solver}solver.txt",
                "a"
            ) as f:
                f.write(errorMessage)
            with open("errors.log", "a") as f:
                f.write(errorMessage)
            break

        try:
            with open(
                f"find_lowest_weight_xor_differentiallinear_trail__ballet_{block_bit}block_{key_bit}key_9rounds 2-1-6 __{solver}solver.txt",
                "a"
            ) as f:
                f.write(json.dumps(trail, indent=4))
                f.write("-" * 60 + f" start={start_date} end={datetime.datetime.now()}\n\n")
        except Exception as e:
            errorMessage = (
                f"args={sys.argv}\n"
                f"Exception occurred during result saving: {repr(e)}\n\n"
                f"Traceback:\n{traceback.format_exc()}"
                + "-" * 60 +
                f" start={start_date} end={datetime.datetime.now()}\n\n"
            )
            with open("errors.log", "a") as f:
                f.write(errorMessage)
