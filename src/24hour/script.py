import os
import subprocess
import datetime
import time
import shutil

begin = datetime.date(2014, 1, 1) # Set the date of data here
end = datetime.date(2014, 12, 30) # We did not use the data of 2/29
path = 'DateWiseData/NormalWinso/2014/'

day = begin
delta = datetime.timedelta(days=1)

#print("==============================\nsubprocess.getstatusoutput(./bin/KeyGen)\n==============================")
#(status, output) = subprocess.getstatusoutput("./bin/KeyGen")
#print(status, output)

print("==============================\nsubprocess.getstatusoutput(make)\n==============================")
(status, output) = subprocess.getstatusoutput('make')
print(status, output)

print("==============================\nsubprocess.getstatusoutput(bin/MakeEncTab_1)\n==============================")
(status, output) = subprocess.getstatusoutput('bin/MakeEncTab_1')
print(status, output)

i = 0
start = time.process_time()

while day <= end:
    today = day.strftime("%Y-%m-%d")
    #print(i, today)

    out_res = open("ctxt_res/test2014.txt", mode='a')
    out_res.write(f"{i},")
    out_res.close()
    out_resp = open("ptxt_res/test2014.txt", mode='a')
    out_resp.write(f"{i},")
    out_resp.close()

    print("==============================\nsubprocess.getstatusoutput(bin/Step1_CS1)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step1_CS1 {path}{today}.txt ptxt_res/test2014.txt Result")
    print(output)

    exit(0)

    print("==============================\nsubprocess.getstatusoutput(bin/Step2_TA1)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step2_TA1 Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/Step3_CS2)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step3_CS2 {today} Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/Step4_TA2)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step4_TA2 {today} Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/Step5_CS3)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step5_CS3 {today} Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/Step6_TA3)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step6_TA3 {today} Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/Step7_CS4)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/Step7_CS4 {today} Result")
    print(status, output)

    print("==============================\nsubprocess.getstatusoutput(bin/CheckRes)\n==============================")
    (status, output) = subprocess.getstatusoutput(f"bin/CheckRes {today} Result ctxt_res/test2014.txt")
    print(status, output)

    shutil.rmtree('Result')
    os.mkdir('Result')
    day += delta
    i += 1

    exit(0)
end = time.process_time()
print(end - start)