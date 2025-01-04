import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import matplotlib.pyplot as plt


xValues = np.array([x for x in range (100)])
xValues = xValues.reshape(-1, 1)
yValues = 46 + 2 * xValues.flatten()

print (yValues)
