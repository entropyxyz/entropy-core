# A python implementation of the partitioning function
# for validators during a session refresh for testing purposes.
curr_validators = [[1,2,3], [4], [5,6,7,8], [11], [12,13,14], [22], [100], [500,501,502,503,504,505]]
next_validators = [[] for _ in  curr_validators]
new_validators = [1,2,5,6,9,10, 14, 100, 500, 501, 300, 200]
new_validators.extend(x for x in range(2000,2100))
unplaced_validators = []
print("")
for new_validator in new_validators:
    exists = False
    for sg, sg_validators in enumerate(curr_validators):
        if new_validator in sg_validators:
            print("# found existing validator: " + str(new_validator) + " at sg: "+str(sg))
            next_validators[sg].append(new_validator)
            exists = True
            break
    if not exists:
        unplaced_validators.append(new_validator)


print("")
print("# unplaced validators: " + ", ".join([str(x) for x in unplaced_validators]))
print("# unbalanced validators: " + ", ".join([str(x) for x in next_validators]))

while unplaced_validators:
    to_place = unplaced_validators.pop()
    min_sg_len = 10000000000000000
    min_sg = 0
    for sg, validators in enumerate(next_validators):
        if len(validators) < min_sg_len:
            min_sg_len = len(validators)
            min_sg = sg
    next_validators[min_sg].append(to_place)


print("# balanced validators: " + ", ".join([str(x) for x in next_validators]))

# found existing validator: 1 at sg: 0
# found existing validator: 2 at sg: 0
# found existing validator: 5 at sg: 2
# found existing validator: 6 at sg: 2
# found existing validator: 14 at sg: 4
# found existing validator: 100 at sg: 6
# found existing validator: 500 at sg: 7
# found existing validator: 501 at sg: 7

# unplaced validators: 9, 10
# unbalanced validators: [1, 2], [], [5, 6], [], [14], [], [100], [500, 501]
# balanced validators: [1, 2], [10], [5, 6], [9], [14], [], [100], [500, 501]
