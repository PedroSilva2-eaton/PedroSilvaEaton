import logging
import uuid
import json

import azure.functions as func

def main(documents: func.DocumentList, inputblob: str, outputblob: func.Out[str], outputblobtable: func.Out[str]) -> str:
    text_to_print = ''
    table_to_print = ''
    data = {}
    table_age = {}
    
    if documents:
        logging.info('number of elements: %s', len(documents))
        
        if documents[0]['index'] == 0:
            text_to_print = ""
            outputblob.set(text_to_print)
            
        text_to_print = inputblob
        for i in range (len(documents)):
            rowKey = str(uuid.uuid4())
            text_to_print = text_to_print + "" + documents[i]['name'] + "/" + str(documents[i]['age']) + "/" + documents[i]['gender'] + " | \n"
            table_age[i] = documents[i]['age']
            data[i] = {
                "PartitionKey": "message",
                "RowKey": rowKey,
                "id": documents[i]['id']
            }
        logging.info(text_to_print)
        outputblob.set(text_to_print)
        # for i in range(len(documents)):
        #     table_to_print = table_to_print + json.dumps(data[i]) + ';'
        table_to_print = json.dumps(data[0])
        outputblobtable.set(table_to_print)