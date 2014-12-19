using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;

namespace sherpanalyzer {
  class Program {
    static void Main(string[] args) {
      List<string> asyncT = new List<string>();
      List<string> errors = new List<string>();  
      Console.WriteLine(System.Environment.NewLine);
      Console.WriteLine("Running automatic full reports on all nmon-based files in this recursive directory...");
      string[] zips = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.zip", SearchOption.AllDirectories).ToArray();
      if (zips.Count() > 0) {
        try {//can you .NET4.5?
        Parallel.ForEach(zips, z => {
          using (ZipArchive archive = ZipFile.OpenRead(z)) {
              foreach (ZipArchiveEntry entry in archive.Entries) {
                if (entry.FullName.Contains("nmon")) {
                  try {//can you unzip that file?
                      entry.ExtractToFile(Path.Combine(z.Substring(0, z.LastIndexOf('\\')), entry.Name), true);
                    Console.WriteLine("Unzipped " + entry.Name);
                  } catch {
                    errors.Add("Had trouble unzipping this file: " + z);
                  }
                }
              }
            }
          
        });
        } catch {
          Console.WriteLine("Your System is not updated to support .NET Framework 4.5, please update!!!");
          errors.Add("Your System is not updated to support .NET Framework 4.5, please update!!!");
          errors.Add("Could not unzip and process, exiting with errors.");
        }
      }
      string[] files = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.*", SearchOption.AllDirectories).Where(name => name.Substring(name.LastIndexOf('\\'), name.Length - name.LastIndexOf('\\')).Contains("nmon")).Where(name => !name.Contains(".zip")).ToArray();
      if(files.Count()<1){
        asyncT.Add("No nmon files were found in this directory... Did I do something wrong????");
      }      
      Parallel.ForEach(files, nmons => {
          try {//only try; do not. unhandled crashes; doing will cause.
            asyncT.Add(readSherpa(nmons, true));
          } catch {//when someone makes readSherpa crash, tell them there was a bad file in there
            errors.Add("Had trouble sherpalyzing this file: " + nmons);
          }
        });
      if (errors.Count == 0) {
        asyncT.Add("No errors sherpalyzing!");
      } else {
        foreach (string e in errors) {
          asyncT.Add(e);
        }
      }
      outputFile(asyncT);
      Console.WriteLine("Finished");
    }

    static void helpFile() {
      Console.WriteLine("Sherpa Analyzer - A.Pedersen 12/4/14");
      Console.WriteLine("Usage: sherpanalyzer <option|file.<nmon|zip>> [<files.nmon>]");
      Console.WriteLine(System.Environment.NewLine + "Options:");
      Console.WriteLine("         all       run on everything .nmon file in current directory");
      Console.WriteLine("         csv       runs all then outputs TOP to csv files" + System.Environment.NewLine);
    }

    static void outputFile(List<string> outputs) {
      using (StreamWriter file = new StreamWriter("output.txt")) {
        file.WriteLine("Sherpa Analyzer - A.Pedersen 12/4/14" + System.Environment.NewLine);
        if (outputs.Count() > 0) {
          foreach (string e in outputs) {
            file.WriteLine(e);
          }
        }       
      }
    }

    static string readSherpa(string filename, bool print) {
      string line;
      string host = "new";
      int cores = 0;
      List<string> summary = new List<string>();
      List<string> times = new List<string>();
      List<double> cpu_all_usr = new List<double>();
      List<double> memsum = new List<double>();
      List<string> disklabels = new List<string>();
      List<double> disksizes = new List<double>();
      List<string> disksizesb = new List<string>();
      List<string> netwuts = new List<string>();
      List<List<string>> topList = new List<List<string>>();
      List<double>[] diskbusy;
      List<double>[] netties;      
      string[] dix;

      string datime = "";
      string ddate = "";
      string ttime = "";
     
      using (StreamReader reader = new StreamReader(filename)) {

        /*read in each line of text then do stuff with it*/
        //small while loop only does maybe 50lines before breaking
        while ((line = reader.ReadLine()) != null) {//this is the prelim loop to make the primary loop go quicker
          summary.Add(line);
          string[] values = line.Split(',');
          if (values[1] == "time") {
            if (values[0] == "AAA")
              ttime = values[2];
              datime = String.Join("",values[2].Split(new[] { ':', '.' }));
          }
          if (values[1] == "date") {
            if (values[0] == "AAA")
              ddate = values[2];
              datime = String.Join("", values[2].Split('-')) + "_"+datime;
          }
          if (values[1] == "host")
            host = values[2];
          if (values[1] == "cpus")
            cores = Convert.ToInt32(values[2]);
          if (values[0] == "NET") {//first line of NET data from the file
            foreach (string nets in values.Skip(2)) { //for all the nets presented on this line (skipping the first 2 garbage lines)
              if(nets != "") netwuts.Add(nets);//all the things, each iface, each bond, eths, los..  everything from the ifconfig
            }
          }
          if (values[0] == "DISKBUSY") {//first line of DISKBUSY holds disk names
            foreach (string diskN in values.Skip(2)) { //for all the disk labels presented on this line (skipping the first 2 garbage lines)
              if(diskN != "") disklabels.Add(diskN);//all sd and dm partitions, just keep it all in there
            }
          }
          if (values[0] == "BBBP"){
            if (values[2] == "/proc/partitions") {
              try {
                dix = values[3].Split(new[] { ' ', '\"' }, StringSplitOptions.RemoveEmptyEntries);
                if (dix[0] != "major") {
                  disksizes.Add(Convert.ToDouble(dix[2])/1000);
                  disksizesb.Add(dix[3]);
                }
              } catch { }
            } else if (values[2] == "/proc/1/stat")
              break;
          }
        }//some background info was gathered from AAA


        netties = new List<double>[netwuts.Count()];
        for (int i = 0; i < netties.Count(); i++) {
          netties[i] = new List<double>();//so many I dont even
        }//we now have netwuts.count netties[]s; each netties is a double list we can add each(EVERY SINGLE) line nmon records
        
        diskbusy = new List<double>[disklabels.Count()];
        for (int i = 0; i < disklabels.Count(); i++) {
          diskbusy[i] = new List<double>();//almost as many I dont even
        }//we now have disklabels.count diskbusy[]s; each diskbusy is a double list we can add each(EVERY SINGLE) line nmon records

          while ((line = reader.ReadLine()) != null) { //Got all the prelim done, now do the rest of the file
            string[] values = line.Split(',');
            /*switch was faster than an if block*/
            switch (values[0]) {
              case "ZZZZ":
                times.Add(values[2]+" "+values[3]);
                break;
              case "TOP":
                List<string> topstuff = new List<string>();
                //TOP,+PID,Time,%CPU,%Usr,%Sys,Size,ResSet,ResText,ResData,ShdLib,MajorFault,MinorFault,Command
                topstuff.Add(values[2].Substring(1, values[2].Length - 1));
                for (int i = 1; i < values.Count(); i++) {
                  if (i != 2) {
                    topstuff.Add(values[i]);
                  }                  
                }
                topList.Add(topstuff);
                  break;
              case "CPU_ALL":
                if (values[2] != "User%") {
                  cpu_all_usr.Add((Convert.ToDouble(values[2]) + Convert.ToDouble(values[3])));
                }
                break;
              case "MEM":
                if (values[2] != "memtotal") {
                  memsum.Add(100.0 * (1 - ((Convert.ToDouble(values[6]) + Convert.ToDouble(values[11]) + Convert.ToDouble(values[14])) / Convert.ToDouble(values[2]))));
                }
                break;
              case "NET":
                Parallel.ForEach(values.Skip(2), (nets, y, i) => {
                  if (nets != "") netties[i].Add(Convert.ToDouble(nets));
                });
                break;
              case "DISKBUSY":
                Parallel.ForEach(values.Skip(2), (disk, y, i) => {
                  diskbusy[i].Add(Convert.ToDouble(disk));
                });
                break;
              //etc
              default: //poison buckets barf pile
                break;
            }//end switch
          }//end while
      }//done file handling
      
	  //inframortions
      string dump = ""; //feels like a bad way to do this, but worked well
      dump += host + " from "+ttime+" "+ddate+" time chunks: " + times.Count + System.Environment.NewLine;
      
	  //CPU
      dump += host + " CPU(%) average: " + cpu_all_usr.Average() + System.Environment.NewLine;
      dump += host + " CPU(%) max: " + cpu_all_usr.Max() + System.Environment.NewLine;
      
	  //MEM
      dump += host+ " MEM(%) average: " + memsum.Average()+System.Environment.NewLine;
      dump += host + " MEM(%) max: " + memsum.Max() + System.Environment.NewLine;
      
	  //DISKBUSY
      for(int i=0;i<disklabels.Count;i++){
        if(disklabels[i].Substring(0,1)!="d"){
          dump += host + " DISKBUSY(%) avg for " + disklabels[i] + ": " + diskbusy[i].Average() + System.Environment.NewLine;
          dump += host + " DISKBUSY(%) max for " + disklabels[i] + ": " + diskbusy[i].Max() + System.Environment.NewLine;
        }
      }
      
	  //DISKBUSY weights
      double sdSum = 0.0;
      double diskweight = 0.0;
      double diskmaxes = 0.0;
      for (int i = 0; i < disksizesb.Count; i++) {
        if (disksizesb[i].Substring(0, 1) == "s") {
          sdSum += disksizes[i];
        }
      }
      for (int i = 0; i < disklabels.Count; i++) {  
        if (disklabels[i].Substring(0, 1) == "s") {
          for (int j = 0; j < disksizesb.Count; j++) {
            if (disksizesb[j] == disklabels[i]) {
              diskweight += (diskbusy[i].Average() * disksizes[j]);
              diskmaxes += (diskbusy[i].Max() * disksizes[j]);
            }
          }
        }
      }
      dump += host + " weighted DISKBUSY(%) avg: " + diskweight / sdSum + System.Environment.NewLine;
      dump += host + " weighted DISKBUSY(%) max: " + diskmaxes / sdSum + System.Environment.NewLine;
      
	  //NET
      for (int i = 0; i < netwuts.Count; i++) {
        if (netwuts[i].Substring(0, 2) != "lo") {//we dont need to see the loopback
          dump += host + " NET average for " + netwuts[i] + ": " + netties[i].Average() + System.Environment.NewLine;
        }
      }
      
      //CSV file stuff
      if (print) {
        string topTitle = "Time,PID,%CPU,%Usr,%Sys,Size,ResSet,ResText,ResData,ShdLib,MajorFault,MinorFault,Command";
        using (StreamWriter file = new StreamWriter(host +"_"+ datime+"_TOP.csv")) {
          file.WriteLine(topTitle);
          for (int i = 0; i < topList.Count; i++) {
            try {
              file.WriteLine(times[Convert.ToInt16(topList[i][0])-1] + "," + string.Join(",", topList[i].Skip(1)));//wat, dats right
            } catch {
              // *shrug do nothing
            }
          }
        }
      }
      Console.WriteLine("Finishing " + host +" from "+datime);
      return (dump);
    } 
  }
}
