import java.text.SimpleDateFormat
import java.util.Date

// dbutils.widgets.remove("eventhub")
dbutils.widgets.text("table", "ehcapture", "Table")

val formatter = new SimpleDateFormat("yyyy-MM-dd");
val dateSelected = formatter.format(new Date());
//println(dateSelected)
dbutils.widgets.text("run_date", dateSelected, "Run date (yyyy-MM-dd)")
dbutils.widgets.text("event_hub", "${EVENTHUB}", "EventHub")
val runDate = dbutils.widgets.get("run_date")
val eventHub = dbutils.widgets.get("event_hub")
val tableName = dbutils.widgets.get("table")
println(runDate)
println(eventHub)
println(tableName)

// In case the table is not there, create it, there's another notebook "create_table_ehcapture" that initializes the table and
// fires a MSCK to repair it as well, but this can work for adding from the present onwards.
spark.sql(s"""
CREATE EXTERNAL TABLE IF NOT EXISTS `$${tableName}` (
  `EnqueuedTimeUtc` STRING, `Body` BINARY
)
PARTITIONED BY (`eventhub` STRING, `day` DATE, `hour` INT)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.avro.AvroSerDe'
STORED AS INPUTFORMAT 'org.apache.hadoop.hive.ql.io.avro.AvroContainerInputFormat' OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.avro.AvroContainerOutputFormat'
LOCATION '${STORAGEACCOUNTACCESS}/raw/capture/${EVENTHUBNAMESPACE}'
""")

for (hour <- 0 to 23) {
  val hourPadded = f"$${hour}%02d"
  val query=s"""
  ALTER TABLE $${tableName} ADD IF NOT EXISTS PARTITION (eventhub='${EVENTHUB}', day='$${runDate}', hour='$${hourPadded}') LOCATION '${STORAGEACCOUNTACCESS}/raw/capture/${EVENTHUBNAMESPACE}/eventhub=${EVENTHUB}/day=$${runDate}/hour=$${hourPadded}'
"""

  println(s"Running query: $${query}")

  spark.sql(query)
}
