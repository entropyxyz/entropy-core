#!/usr/bin/python3
# A python implementation of the partitioning function
# for validators during a session refresh for testing purposes.
curr_validators = [[1,2,3], [4], [5,6,7,8], [11], [12,13,14], [22], [100], [500,501,502,503,504,505]]
new_validators = [1,2,5,6,9,10, 14, 100, 500, 501, 300, 200]
next_validators = [[] for _ in  curr_validators]
unplaced_validators = []

print("# Starting validator set:\n#\t"+":".join([str(x) for idx, x in enumerate(curr_validators)]))
print("# Incoming list of validators:\n#\t"+", ".join([str(x) for x in new_validators]))
for new_validator in new_validators:
    exists = False
    for sg, sg_validators in enumerate(curr_validators):
        if new_validator in sg_validators:
            next_validators[sg].append(new_validator)
            exists = True
            break
    if not exists:
        unplaced_validators.append(new_validator)


print("# unplaced validators: \n#\t" + ", ".join([str(x) for x in unplaced_validators]))
print("# unbalanced validator set: \n#\t" + ", ".join([str(x) for x in next_validators]))

while unplaced_validators:
    to_place = unplaced_validators.pop()
    min_sg_len = 10000000000000000
    min_sg = 0
    for sg, validators in enumerate(next_validators):
        if len(validators) < min_sg_len:
            min_sg_len = len(validators)
            min_sg = sg
    next_validators[min_sg].append(to_place)

print("# new, balanced validator set: \n#\t" + ", ".join([str(x) for x in next_validators]))
#
# Starting validator set:
#       [1, 2, 3]:[4]:[5, 6, 7, 8]:[11]:[12, 13, 14]:[22]:[100]:[500, 501, 502, 503, 504, 505]
# Incoming list of validators:
#       1, 2, 5, 6, 9, 10, 14, 100, 500, 501, 300, 200
# unplaced validators: 
#       9, 10, 300, 200
# unbalanced validator set: 
#       [1, 2], [], [5, 6], [], [14], [], [100], [500, 501]
# new, balanced validator set: 
#       [1, 2], [200, 9], [5, 6], [300], [14], [10], [100], [500, 501]