from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher

start_round = 3
end_round = 13
weight = 0

for r in range(start_round, end_round):
    print(f"current round:{r}")
    cipher = BalletBlockCipher(number_of_rounds=r)
    model = SatXorLinearModel(cipher)

    print(f"current weight:{weight}")
    trail = model.find_lowest_weight_xor_linear_trail(
            solver_name="PARKISSAT_EXT",
            options=["-c=80"],
            start_weight=weight)
    if trail['total_weight'] != None:
        weight = int(trail['total_weight'])
        f = open(f'trail_linear_round{r}_weight{weight}', 'w')
        f.write(str(trail))
        f.close()
