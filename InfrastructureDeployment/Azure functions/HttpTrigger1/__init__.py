import logging
import uuid
import json

import azure.functions as func


def main(req: func.HttpRequest, documents: func.DocumentList, outputblob: func.Out[bytes], outputblobtable: func.Out[str]) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    average = 0
    int_average = 0
    string_to_write = ""
    nbr_item = 0

    if not documents:
        logging.warning("documents not found")
    else:
        for item in documents:
            if item["id"]:
                nbr_item = nbr_item + 1
                average = average + item['y']
                string_to_write = string_to_write + str(item['ds']) + " : " + str(item['y']) + " \n "
        average = average / nbr_item
        string_to_write = string_to_write + "average = " + str(average) + "\n"
        logging.info(string_to_write)
        logging.info('documents len = %s', nbr_item)
        outputblob.set(string_to_write)
        rowKey = str(uuid.uuid4())
        data = {
                "PartitionKey": "message",
                "RowKey": rowKey,
                "average": average,
                "id": documents[0]['id']
            }
        outputblobtable.set(json.dumps(data))
        int_average = int(average)
    return func.HttpResponse( f"This HTTP triggered function executed successfully. average y power is {int_average}kW", status_code=200 )
