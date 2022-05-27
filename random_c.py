import random
import string
import sys
def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))
#print ("Random String is ", randomString() )
#print ("Random String is ", randomString(10) )
#print ("Random String is ", randomString(10) )

fp = open("random.txt","w")
fp.close()
ubound = int(sys.argv[1])
for i in range (ubound):
    data = randomString(100000)
    fp = open("random.txt","a")
    fp.write(data)
    fp.close()
