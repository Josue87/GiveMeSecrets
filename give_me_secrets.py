from subprocess import Popen, PIPE
import sys
import os
import importlib
import argparse
import re
from rules import get_rules
from banner import get_banner


class GiveMeSecrets:

    def __init__(self):
        self.report_name = None
        self.repo = None
        self.number_secrets = 0
        self.functions = {
            1: self._check_git_repo,
            2: self._check_pip_repo,
            3: self._check_npm_repo
        }

    def set_report_name(self, name):
        self.report_name = "./results/" + name
    
    def set_repo(self, repo):
        self.repo = repo

    def check_repo(self, option):
        if self._check_attrs():
            print("Please configure repo and report name")
            return
        try:
            self.functions.get(option)()
            print("Done!")
            print(f"Please check: {self.report_name}.", end=" ")
            if self.number_secrets:
                print(f"Total records found: {self.number_secrets}")
            else:
                print("Document empty. No data found")
        except Exception as e:
            print(e)

    def _check_npm_repo(self):
        print("Working: NPM Repo...")
        repo_command = f"npm pack {self.repo}"
        result = Popen(repo_command.split(" "), stdout=PIPE, stderr=PIPE)
        err = result.stderr.read().decode()
        if err:
            print(err)
            return
        tar = result.stdout.read().decode().strip()
        if tar:
            os.system(f"mv {tar} ./downloads" )
            tar = f"./downloads/{tar}"
            try:       
                # Extract tar
                result = Popen(["tar", "-xvzf", tar], stdout=PIPE, stderr=PIPE)
                err = result.stderr.read()   
                if not err:
                    directory = "package"
                    os.system(f"mv {directory} ./downloads" )
                    directory = "./downloads/" + directory
                    files = self._get_files(directory)
                    self._start_analysis(files)
                    os.system(f"rm -rf {directory}")
                    os.system(f"rm {tar}")
                else:
                    print(err)
            except Exception as e:
                print(e)
    
    def _check_pip_repo(self):
        print("Working: Pip Repo...")
        repo_command = f"pip download {self.repo} -d ./downloads"
        result = Popen(repo_command.split(" "), stdout=PIPE, stderr=PIPE)
        err = result.stderr.read().decode()
        if err and not "WARNING" in err:
            print(err)
            return
        try:
            result = Popen([f"ls ./downloads/*{self.repo}*.tar.gz"], stdout=PIPE, stderr=PIPE, shell=True)
            tar = result.stdout.read().decode().strip()
            # Extract tar
            result = Popen(["tar", "-xvzf", tar], stdout=PIPE, stderr=PIPE)
            err = result.stderr.read()   
            if not err:
                directory = result.stdout.read().decode().split("\n")[0]
                os.system(f"mv {directory} ./downloads" )
                directory = "./downloads/" + directory
                files = self._get_files(directory)
                self._start_analysis(files)
                os.system(f"rm -rf {directory}")
                os.system(f"rm {tar}")
            else:
                print(err)
        except Exception as e:
            print(e)
    
    def _check_git_repo(self):
        print("Working: Git Repo...")
        repo_command = f"git clone {self.repo}"
        print(f"Cloning repo: {self.repo}")
        result = Popen(repo_command.split(" "), stdout=PIPE, stderr=PIPE)
        directory = self.repo.split("/")[-1].replace(".git", "")
        err = result.stderr.read().decode()
        if err and not f"'{directory}'" in err:
            print(err)
            return
        try:
            os.system(f"mv {directory} ./downloads")
            directory = "./downloads/" + directory
            files = self._get_files(directory)
            self._start_analysis(files)
            os.system(f"rm -rf {directory}")
        except Exception as e:
            print(e)
    
    def _check_attrs(self):
        return (not self.repo) or (not self.report_name)

    def _get_files(self, directory):
        all_files = []
        for (p, _, fs) in os.walk(directory):
            for f in fs:
                all_files.append(os.path.join(p, f))
        return all_files

    def _start_analysis(self, files):
        with open(self.report_name, "w") as write_file:
            for f in files:
                try:
                    code = ""
                    with open(f, "r") as open_file:
                        code = open_file.read()
                    data = self._check_code(code)    
                    if data:
                        self.number_secrets += len(data)
                        self._dump_results(f, data, write_file)
                except:
                    pass
        
    def _check_code(self, code):
        rules = get_rules()
        data = []
        i = 1
        for line in code.splitlines():
            for key, rule in rules.items():
                if rule.findall(line):
                    data.append({"Line": i, "Code": line.strip(), "Rule": key})
            i += 1
        return data

    def _dump_results(self, code_file, vulnerabilities, file_to_dump):
        f = code_file.replace("./downloads/", "")
        file_to_dump.write(f + "\n")
        file_to_dump.write("-"*len(f)+ "\n")
        for v in vulnerabilities:
            for k,v in v.items():
                file_to_dump.write(f"{k}: {v}"+ "\n")
            file_to_dump.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-r', '--repo', help='Repository to review', required=True)
    parser.add_argument('-0', '--option', help='1 - GitHub; 2 - pip; 3 - npm', type=int, default=1)
    args = parser.parse_args()
    repo = args.repo
    option = args.option
    print(get_banner())
    if option == 1:
        regex = re.compile(r"^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*.git\/?$", re.IGNORECASE)
        if regex.match(repo):
            file_name = repo.split("/")[-1].replace(".git", "") + ".txt"
        else:
            print("The repository is going to be cloned, the URL is incorrect... An example: https://github.com/user/project.git")
            sys.exit(0)
    elif option > 3:
        print("Bad option: 1 - GitHub; 2 - pip; 3 - npm")
        sys.exit(0)
    else:
        file_name = repo + ".txt"
    gs = GiveMeSecrets()
    gs.set_repo(repo)
    gs.set_report_name(file_name)
    gs.check_repo(option)
     