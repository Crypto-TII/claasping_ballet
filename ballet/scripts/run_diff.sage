from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher

start_round = 3
end_round = 13
weight = 0

for r in range(start_round, end_round):
    print(f"current round:{r}")
    cipher = BalletBlockCipher(number_of_rounds=r)
    model = SatXorDifferentialModel(cipher)

    print(f"current weight:{weight}")
    trail = model.find_lowest_weight_xor_differential_trail(
            solver_name="PARKISSAT_EXT",
            options=["-c=80"],
            start_weight=weight)
    if trail['total_weight'] != None:
        weight = int(trail['total_weight'])
        f = open(f'trail_differential_round{r}_weight{weight}', 'w')
        f.write(str(trail))
        f.close()
