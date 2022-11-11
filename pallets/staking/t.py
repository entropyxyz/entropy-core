validators = [1,2,3,4,5]
signing_party_size = 2

subgroup_size = int(len(validators) / signing_party_size)
remainder = len(validators) % signing_party_size


for sg in range(signing_party_size):
    for sidx in range(sg*subgroup_size, sg*subgroup_size+(subgroup_size)):
        print(sg, sidx)
