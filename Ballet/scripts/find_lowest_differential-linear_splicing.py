import sys
import json
import traceback
import datetime
import itertools

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import (
    SatDifferentialLinearModel,
)
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def hex_to_bitlist(hex_str):
    val_int = int(hex_str, 16)
    bit_len = (len(hex_str) - 2) * 4
    return integer_to_bit_list(val_int, bit_len, "big")


intermediate_outputs = {
    # "plaintext": "0x40280484000111888004110844008040",
    "key": "0x00000000000000000000000000000000",
    "intermediate_output_0_10": "0x00011188000020100000020180041108",
    "intermediate_output_1_10": "0x00002010000004000000000200000201",
    "intermediate_output_2_10": "0x00000400000000000000000000000002",
    "intermediate_output_3_10": "0x00000000000100000001000000000000",
    "intermediate_output_4_10": "0x00010000000000000000000000010000",
    "intermediate_output_5_10": "0x00000000004000008000000000000000",
    "intermediate_output_6_10": "0x00400000800001000000201080000000",
    "intermediate_output_8_10": "0x00000000000040000000400000002000",
    "intermediate_output_9_10": "0x00000000000000001800000000000000",
    "intermediate_output_10_10": "0x00000000000000000000000018000000",
    "intermediate_output_11_10": "0x20000000000000000000080020000000",
}

solver = "PARKISSAT_EXT"
core = 16

block_bit, key_bit = (128, 128)
round_differential = 7
intermediate_rounds = 1
for round_linear in range(7,8):
    number_of_rounds = round_differential + intermediate_rounds + round_linear

    ballet = BalletBlockCipher(
        block_bit_size=block_bit, key_bit_size=key_bit, number_of_rounds=number_of_rounds
    )

    middle_part_components = []
    bottom_part_components = []

    middle_part_components.append(ballet.get_components_in_round(round_differential))
    for round_number in range(round_differential + intermediate_rounds, number_of_rounds):
        bottom_part_components.append(ballet.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    fixed_values = []
    ciphertext_difference = set_fixed_variables(
        component_id=f"cipher_output_{number_of_rounds - 1}_10",
        constraint_type="not_equal",
        bit_positions=range(block_bit),
        bit_values=(0,) * block_bit,
    )
    intermediate_value = set_fixed_variables(
        component_id="intermediate_output_7_10",
        constraint_type="equal",
        bit_positions=range(128),
        bit_values=list(
            "10000000000000000000000100000000???????????????????????100000000??????????????????1000000000000000000000000000000010000000010000"
        ),
    )
    fixed_values.extend([ciphertext_difference, intermediate_value])

    for var_name, hex_val in intermediate_outputs.items():
        bits = hex_to_bitlist(hex_val)
        bit_indices = list(range(len(bits)))
        fixed_values.append(set_fixed_variables(var_name, "equal", bit_indices, bits))

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat = SatDifferentialLinearModel(ballet, component_model_list)

    try:
        trail = sat.find_lowest_weight_xor_differential_linear_trail(
            fixed_values=fixed_values,
            solver_name=solver,
            num_unknown_vars=block_bit - 1,
            options=[f"-c={core}"],
        )
        trail["cipher"] = str(trail["cipher"])

        fname = f"find_lowest_weight_xor_differentiallinear_sliced_trail__ballet_{block_bit}block_{key_bit}key_{number_of_rounds}rounds7-1-4+{round_linear - 4}sliced__{solver}solver_{core}core.json"
        with open(fname, "w") as f:
            f.write(json.dumps(trail, indent=4))

        print(f"Done {fname}")
    except Exception as e:
        with open("errors.log", "a") as fp:
            errorMessage = (
                f"args={sys.argv}\n"
                f"Exception occurred during SAT: {repr(e)}\n\n"
                f"Traceback:\n{traceback.format_exc()}"
                + "-" * 60 
                + f" start={start_date} end={datetime.datetime.now()}\n\n"
            )
            fp.write(errorMessage)
