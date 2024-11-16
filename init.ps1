# �ж��Ƿ��ѽ�ԭʼ��Զ�ֿ̲���origin������Ϊgithub
function Is-Origin-Renamed {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "github") {
            return $true
        }
    }
    return $false
}

# �ж��Ƿ������gitlabԶ�ֿ̲�
function Is-Gitlab-Added {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "gitlab") {
            return $true
        }
    }
    return $false;
}

$renamed = Is-Origin-Renamed
if ($renamed) {
    Write-Host "githubԶ�ֿ̲����������������ٴβ�����"
}
else {
    git remote rename origin github
    Write-Host "githubԶ�ֿ̲⣨origin����������Ϊgithub��"
}

$gitlabadded = Is-Gitlab-Added
if ($gitlabadded) {
    Write-Host "��ǰgithub�ֿ����빫˾�ڲ�gitlab�ֿ������ɣ������ٴβ�����"
}
else {
    git remote add gitlab http://gitlab.lnwlzb.com/jy/jy-crates/crate-ukey-skf.git
    git push -u gitlab main
    Write-Host "githubԶ�ֿ̲��ѹ�������˾�ڲ�gitlab�������˳�ʼ��push��"
}

# ִ���ⲿ���ʵ���������˸�������ȥ�����������߲���Ҫ��ô��
# $process = Start-Process "git" -ArgumentList "remote", "-v" -PassThru
# $process.WaitForExit()
# Write-Host "git remote -v ����ִ�н���"