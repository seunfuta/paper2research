import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
import sys


Prob = sys.argv[1]

fpr = dict()
tpr = dict()
roc_auc = dict()

fpr, tpr, _  = roc_curve(GroundTruth,Prob)
roc_auc = auc(fpr, tpr)

plt.figure()
lw = 2
plt.plot(fpr,tpr,color="darkorange",lw=lw,label="ROC curve (area = %0.2f)" % roc_auc,)
plt.plot([0, 1], [0, 1], color="navy", lw=lw, linestyle="--")
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Receiver operating characteristic example")
plt.legend(loc="lower right")
plt.show()