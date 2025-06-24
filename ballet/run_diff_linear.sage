from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, _update_component_model_types_for_truncated_components, _update_component_model_types_for_linear_components
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, differential_linear_checker_for_permutation, differential_linear_checker_for_block_cipher_single_key
import itertools


cipher = BalletBlockCipher(number_of_rounds=number_of_rounds)
for par in round_parameters:
    middle_round = par[0]
    bottom_round = par[1]
    print(f"middle round: {middle_round}, bottom round: {bottom_round}")
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(middle_round, bottom_round):
        middle_part_components.append(cipher.get_components_in_round(round_number))
    for round_number in range(bottom_round, number_of_rounds):
        bottom_part_components.append(cipher.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(128),
        bit_values=(0,) * 128
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(128),
        bit_values=(0,) * 128
    )


    ciphertext_difference = set_fixed_variables(
        component_id=f'cipher_output_{number_of_rounds-1}_10',
        constraint_type='not_equal',
        bit_positions=range(128),
        bit_values=(0,) * 128
    )

    component_model_types = _generate_component_model_types(cipher)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(cipher, component_model_types)

    for w in range(start_weight, end_weight+1):
        print(f"current weight:{w}")
        trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
            weight=w, fixed_values=[key, plaintext, ciphertext_difference], solver_name="PARKISSAT_EXT",
            options=["-c=150"], num_unknown_vars=31)
        if trail['total_weight'] != None:
            tw = trail['total_weight']
            f = open(f'trail_diff_linear_round{number_of_rounds}_weight{tw}_middle{middle_round}_bottom{bottom_round}', 'w')
            f.write(str(trail))
            f.close()
            break

