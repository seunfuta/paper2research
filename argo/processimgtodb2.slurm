#!/bin/sh


#SBATCH --job-name=processimgtodb
#SBATCH --partition=normal

#SBATCH --output=/scratch/%u/%x-%N-%j.out  # Output file
#SBATCH --error=/scratch/%u/%x-%N-%j.err   # Error file

#SBATCH --mail-type=BEGIN,END,FAIL         # ALL,NONE,BEGIN,END,FAIL,REQUEUE,..
#SBATCH --mail-user=oadegbeh@gmu.edu     # Put your GMU email address here


#SBATCH --mem=32G        # Total memory needed per task (units: K,M,G,T)
#SBATCH --time=0-02:00   # Total time needed for job: Days-Hours:Minutes

#SBATCH --ntasks=51   # 50 workers, 1 manager

## Load the relevant modules needed for the job
module load gnu10
module load openmpi
module load python

## Run your program or script
mpirun -np $SLURM_NTASKS python -m mpi4py.futures processimgtodb.py