Attribute VB_Name = "Approval"
Option Explicit

Private Const ApprovalLimit As Currency = 100000

Public Function RequiresApproval(ByVal amount As Currency, ByVal approved As Boolean) As Boolean
    If amount >= ApprovalLimit Then
        RequiresApproval = Not approved
    Else
        RequiresApproval = False
    End If
End Function

Public Sub SaveOrder(ByVal amount As Currency)
    If RequiresApproval(amount, False) Then
        MsgBox "Manager approval is required"
    Else
        Worksheets("Orders").Range("A1").Value = amount
    End If
End Sub
