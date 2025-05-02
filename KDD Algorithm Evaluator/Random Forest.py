from sklearn.ensemble import IsolationForest
print ("Isolation Forest Model")
isolationForest = IsolationForest(random_state=42)
start = time()
isolationForest = isolationForest.fit(xTrain, yTrain)
end = time()
evaluationMetric(isolationForest, xTrain, yTrain, xTest, yTest)
result = end - start
print('%.3f seconds' % result)