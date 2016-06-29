#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import argparse, pickle

import pandas as ps
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report

def preprocess(data, seed=None):
    # Избавляемся от ненужных протоколов:
    drop_protos = ["Unknown", "Unencryped_Jabber", "NTP", "Apple"]
    replace_protos = [("SSL_No_Cert", "SSL")]
    data = data[~data["proto"].isin(drop_protos)]
    for old_proto, new_proto in replace_protos:
        data = data.replace(old_proto, new_proto)

    # Перемешиваем данные:
    if seed:
        np.random.seed(seed)
        data = data.iloc[np.random.permutation(len(data))]

    # Масштабируем и маркируем:
    scaler = StandardScaler()
    labeler = LabelEncoder()
    X = scaler.fit_transform(data.drop(["proto", "subproto"], axis=1))
    y = labeler.fit_transform(data["proto"])

    cols = [col for col in data.columns if col not in ("proto", "subproto")]
    return ps.concat([ps.DataFrame(X, columns=cols),
                ps.DataFrame({"proto": y})], axis=1), scaler, labeler

def split_data(data):
    proto_clusters = [data[data["proto"] == proto] for proto in data["proto"].unique()]
    train_clusters = []
    test_clusters = []
    for cluster in proto_clusters:
        split_index = len(cluster)//3
        train_clusters.append(cluster.iloc[:split_index])
        test_clusters.append(cluster.iloc[split_index:])
    data_train = ps.concat(train_clusters)
    data_test = ps.concat(test_clusters)
    return data_train, data_test

def train_model(data_train, seed):
    X_train = data_train.drop(["proto"], axis=1)
    y_train = data_train["proto"]
    model = RandomForestClassifier(27, "entropy", 9, random_state=seed)
    model.fit(X_train, y_train)
    return model

def score_model(model, data_test, labeler):
    X_test = data_test.drop(["proto"], axis=1)
    y_test = data_test["proto"]
    y_predicted = model.predict(X_test)

    true_labels = labeler.inverse_transform(y_test)
    predicted_labels = labeler.inverse_transform(y_predicted)

    print feature_importances_report(model, X_test.columns)
    print "\n", classification_report(true_labels, predicted_labels)
    print cross_class_report(true_labels, predicted_labels)

def cross_class_report(y, p):
    classes = np.unique(y)
    res = ps.DataFrame({"y": y, "p": p}, index=None)
    table = ps.DataFrame(index=classes, columns=classes)
    for true_cls in classes:
        tmp = res[res["y"] == true_cls]
        for pred_cls in classes:
            table[pred_cls][true_cls] = len(tmp[tmp["p"] == pred_cls])
    return table

def feature_importances_report(model, columns):
    imp = {col: imp for imp, col
        in zip(model.feature_importances_, columns)}
    assert len(imp) == len(columns)
    return "\n".join("{}{}".format(str(col).ljust(25), imp)
        for col, imp in sorted(imp.items(), key=(lambda x: -x[1])))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="csv file")
    parser.add_argument("-o", "--output", help="output model into file", metavar="FILE")
    parser.add_argument("-r", "--random", help="random seed value", metavar="SEED", type=int)
    args = parser.parse_args()

    data = ps.read_csv(args.file)
    data, scaler, labeler = preprocess(data, args.random)
    data_train, data_test = split_data(data)
    model = train_model(data_train, args.random)
    score_model(model, data_test, labeler)

    if args.output:
        pickle.dump((model, scaler, labeler), open(args.output, "wb"))
        print "\nМодель успешно записана в файл '{}'.".format(args.output)

if __name__ == "__main__":
    main()