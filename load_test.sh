
#!/bin/bash

FILE_PATH="sample.jpg"
FORMAT="jpg"
URL="http://ec2-3-24-124-213.ap-southeast-2.compute.amazonaws.com:8080/personal"

for i in {1..1000}
do
    echo "Uploading and converting image $i..."
    curl -X POST -F "file=@$FILE_PATH" -F "format=$FORMAT" $URL &
done


wait
echo "Load test completed."