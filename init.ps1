# �ж��Ƿ��ѽ�ԭʼ��Զ�ֿ̲���origin������Ϊgitlab
function Is-Origin-Renamed {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "gitlab") {
            return $true
        }
    }
    return $false
}

# �ж��Ƿ������githubԶ�ֿ̲�
function Is-Gitlhub-Added {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "github") {
            return $true
        }
    }
    return $false;
}

$renamed = Is-Origin-Renamed
if ($renamed) {
    Write-Host "gitlabԶ�ֿ̲����������������ٴβ�����"
}
else {
    git remote rename origin gitlab
    Write-Host "gitlabԶ�ֿ̲⣨origin����������Ϊgitlab��"
}

$githubadded = Is-Gitlhub-Added
if ($githubadded) {
    Write-Host "��ǰgitlab�ֿ�����github�ֿ������ɣ������ٴβ�����"
}
else {
    git remote add github https://github.com/abnermu/crate-ukey-skf.git
    git push -u github main
    Write-Host "gitlabԶ�ֿ̲��ѹ�����github�������˳�ʼ��push��"
}

# ִ���ⲿ���ʵ���������˸�������ȥ�����������߲���Ҫ��ô��
# $process = Start-Process "git" -ArgumentList "remote", "-v" -PassThru
# $process.WaitForExit()
# Write-Host "git remote -v ����ִ�н���"