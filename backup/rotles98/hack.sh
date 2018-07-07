cp /ex.py ./

cp /base.sh ./nc.sh
pwd=`pwd`
echo "	nc -l -p 4444 -e ./"${pwd##/*/} >> ./nc.sh
echo "done" >> ./nc.sh

cp /debug.py ./
