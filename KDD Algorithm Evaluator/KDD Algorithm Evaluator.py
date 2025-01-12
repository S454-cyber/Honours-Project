#Source Used: https://www.kaggle.com/code/eneskosar19/intrusion-detection-system-nsl-kdd#6.3-EVALUATION

#IMPORTING LIBRARIES

#Importing the numpy library (adding support for large, multi-dimensional arrarys and matricies).
#Importing Pandas library (data manipulation and analysis).
#Importing Matplotlib library (Creating various forms of data visullisations).
#Importing seaborn library (Creating high-level data visualisation interfaces).
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

import warnings
warnings.filterwarnings ('ignore')
#%matplotlib warnings: A magical function that is only valid in Jupyter notebooks.
#Commented out as it is not valid in python.
pd.set_option ('display.float_format', lambda x: '%.3f' % x)
plt.rcParams ["figure.figsize"] = (10,6)

df_0 = pd.read_csv ("KDDTrain+.txt") 
df = df_0.copy()
df.head()


