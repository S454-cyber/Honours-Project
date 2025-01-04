import numpy as np

#Creating a fake dataset to use against a linear regression model
xValues = [i for i in range(11)]
xTrain = np.array(xValues, dtype=np.float32)
xTrain = xTrain.reshape(-1, 1)

yValues = [2*i + 1 for i in xValues]
yTrain = np.array(yValues, dtype=np.float32)
yTrain = yTrain.reshape(-1, 1)

#print(xTrain)
#print (yTrain)