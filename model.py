#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import argparse, pickle

import pandas as ps
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report

def preprocess(data, seed=None):
    '''
        Осуществить предварительную очистку данных,
        масштабирование и маркировку.
        Аргументы:
            data - DataFrame таблицы признаков
            seed - семя генератора псевдослучайных чисел
        Возвращает:
            DataFrame с обработанной таблицей признаков,
            StandardScaler,
            LabelEncoder
    '''

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
    '''
        Разделить таблицу признаков на три части
        так, чтобы каждый протокол одинаково
        присутствовал в каждой части.
        Аргументы:
            data - DataFrame таблицы признаков
        Возвращает:
            Список из трёх DataFrame, каждый
            размером 1/3 от оригинала
    '''
    proto_clusters = [data[data["proto"] == proto] for proto in data["proto"].unique()]
    clusters = [[], [], []]
    for cluster in proto_clusters:
        split_index = len(cluster)//3
        for i in range(3):
            clusters[i].append(
                cluster.iloc[i*split_index : (i+1)*split_index])
    return [ps.concat(clus) for clus in clusters]

def train_model(data_train, seed=None):
    '''
        Обучить модель на таблице признаков.
        Аргументы:
            data_train - DataFrame обучающей выборки
            seed - семя генератора псевдослучайных чисел
        Возвращает:
            Обученную модель RandomForest
    '''
    X_train = data_train.drop(["proto"], axis=1)
    y_train = data_train["proto"]
    model = RandomForestClassifier(27, "entropy", 9, random_state=seed)
    model.fit(X_train, y_train)
    return model

def score_model(model, data_test, labeler):
    '''
        Оценить производительность модели,
        выведя в стандартный вывод три таблицы:
        важности признаков, значения полноты и
        точности для каждого класса, реальные
        и предсказанные классы.
        Аргументы:
            model - обученная модель
            data_test - проверочаня выборка
            labeler - LabelEncoder данной выборки
        Возвращает:
            Ничего
    '''
    X_test = data_test.drop(["proto"], axis=1)
    y_test = data_test["proto"]
    y_predicted = model.predict(X_test)

    true_labels = labeler.inverse_transform(y_test)
    predicted_labels = labeler.inverse_transform(y_predicted)

    print feature_importances_report(model, X_test.columns)
    print "\n", classification_report(true_labels, predicted_labels)
    print cross_class_report(true_labels, predicted_labels)

def cross_class_report(y, p):
    '''
        Составить таблицу реальных и предсказанных
        классов.
        Аргументы:
            y - numpy-массив реальных меток классов
            p - numpy-массив предсказанных меток классов
        Возвращает:
            DataFrame
    '''
    classes = np.unique(y)
    res = ps.DataFrame({"y": y, "p": p}, index=None)
    table = ps.DataFrame(index=classes, columns=classes)
    for true_cls in classes:
        tmp = res[res["y"] == true_cls]
        for pred_cls in classes:
            table[pred_cls][true_cls] = len(tmp[tmp["p"] == pred_cls])
    return table

def feature_importances_report(model, columns):
    '''
        Составить отчёт о важности признаков.
        Аргументы:
            model - обученная модель RandomForest
            columns - список текстовых наименований
                признаков
        Возвращает:
            Отчёт в виде строки
    '''
    imp = {col: imp for imp, col
        in zip(model.feature_importances_, columns)}
    assert len(imp) == len(columns)
    return "\n".join("{}{:.4f}".format(str(col).ljust(25), imp)
        for col, imp in sorted(imp.items(), key=(lambda x: -x[1])))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="csv file")
    parser.add_argument("-o", "--output", help="output model into file", metavar="FILE")
    parser.add_argument("-r", "--random", help="random seed value", metavar="SEED", type=int)
    args = parser.parse_args()

    data = ps.read_csv(args.file)
    data, scaler, labeler = preprocess(data, args.random)

    clusters = split_data(data)
    for i, data_train in enumerate(clusters):
        print("\n\n*** FOLD: {} ***\n".format(i+1))
        data_test = ps.concat([c for c in clusters if c is not data_train])
        model = train_model(data_train, args.random)
        score_model(model, data_test, labeler)

    if args.output:
        pickle.dump((model, scaler, labeler), open(args.output, "wb"))
        print "\nМодель успешно записана в файл '{}'.".format(args.output)

if __name__ == "__main__":
    main()