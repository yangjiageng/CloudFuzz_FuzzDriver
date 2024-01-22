package fuzzing

import (
	raftpb "go.etcd.io/etcd/raft/v3/raftpb"
	walpb "go.etcd.io/etcd/server/v3/storage/wal/walpb"
	v3electionpb "go.etcd.io/etcd/server/v3/etcdserver/api/v3election/v3electionpb"
	leasepb "go.etcd.io/etcd/server/v3/lease/leasepb"
	authpb "go.etcd.io/etcd/api/v3/authpb"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	membershippb "go.etcd.io/etcd/api/v3/membershippb"
	etcdserverpb "go.etcd.io/etcd/api/v3/etcdserverpb"
	v3lockpb "go.etcd.io/etcd/server/v3/etcdserver/api/v3lock/v3lockpb"
	snappb "go.etcd.io/etcd/server/v3/etcdserver/api/snap/snappb"
	rpcpb "go.etcd.io/etcd/tests/v3/functional/rpcpb"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzAPIMarshal(data []byte) int {
	if len(data)<10{ return 0 }
	funcOp := int(data[0])%148
	data2 := data[1:]
	switch funcOp {
	case 0:
		_ = FuzzauthpbUserAddOptions(data2)

	case 1:
		_ = FuzzauthpbUser(data2)

	case 2:
		_ = FuzzauthpbPermission(data2)

	case 3:
		_ = FuzzauthpbRole(data2)

	case 4:
		_ = FuzzetcdserverpbRequest(data2)

	case 5:
		_ = FuzzetcdserverpbMetadata(data2)

	case 6:
		_ = FuzzetcdserverpbRequestHeader(data2)

	case 7:
		_ = FuzzetcdserverpbInternalRaftRequest(data2)

	case 8:
		_ = FuzzetcdserverpbEmptyResponse(data2)

	case 9:
		_ = FuzzetcdserverpbInternalAuthenticateRequest(data2)

	case 10:
		_ = FuzzetcdserverpbResponseHeader(data2)

	case 11:
		_ = FuzzetcdserverpbRangeRequest(data2)

	case 12:
		_ = FuzzetcdserverpbRangeResponse(data2)

	case 13:
		_ = FuzzetcdserverpbPutRequest(data2)

	case 14:
		_ = FuzzetcdserverpbPutResponse(data2)

	case 15:
		_ = FuzzetcdserverpbDeleteRangeRequest(data2)

	case 16:
		_ = FuzzetcdserverpbDeleteRangeResponse(data2)

	case 17:
		_ = FuzzetcdserverpbRequestOp(data2)

	case 18:
		_ = FuzzetcdserverpbResponseOp(data2)

	case 19:
		_ = FuzzetcdserverpbCompare(data2)

	case 20:
		_ = FuzzetcdserverpbTxnRequest(data2)

	case 21:
		_ = FuzzetcdserverpbTxnResponse(data2)

	case 22:
		_ = FuzzetcdserverpbCompactionRequest(data2)

	case 23:
		_ = FuzzetcdserverpbCompactionResponse(data2)

	case 24:
		_ = FuzzetcdserverpbHashRequest(data2)

	case 25:
		_ = FuzzetcdserverpbHashKVRequest(data2)

	case 26:
		_ = FuzzetcdserverpbHashKVResponse(data2)

	case 27:
		_ = FuzzetcdserverpbHashResponse(data2)

	case 28:
		_ = FuzzetcdserverpbSnapshotRequest(data2)

	case 29:
		_ = FuzzetcdserverpbSnapshotResponse(data2)

	case 30:
		_ = FuzzetcdserverpbWatchRequest(data2)

	case 31:
		_ = FuzzetcdserverpbWatchCreateRequest(data2)

	case 32:
		_ = FuzzetcdserverpbWatchCancelRequest(data2)

	case 33:
		_ = FuzzetcdserverpbWatchProgressRequest(data2)

	case 34:
		_ = FuzzetcdserverpbWatchResponse(data2)

	case 35:
		_ = FuzzetcdserverpbLeaseGrantRequest(data2)

	case 36:
		_ = FuzzetcdserverpbLeaseGrantResponse(data2)

	case 37:
		_ = FuzzetcdserverpbLeaseRevokeRequest(data2)

	case 38:
		_ = FuzzetcdserverpbLeaseRevokeResponse(data2)

	case 39:
		_ = FuzzetcdserverpbLeaseCheckpoint(data2)

	case 40:
		_ = FuzzetcdserverpbLeaseCheckpointRequest(data2)

	case 41:
		_ = FuzzetcdserverpbLeaseCheckpointResponse(data2)

	case 42:
		_ = FuzzetcdserverpbLeaseKeepAliveRequest(data2)

	case 43:
		_ = FuzzetcdserverpbLeaseKeepAliveResponse(data2)

	case 44:
		_ = FuzzetcdserverpbLeaseTimeToLiveRequest(data2)

	case 45:
		_ = FuzzetcdserverpbLeaseTimeToLiveResponse(data2)

	case 46:
		_ = FuzzetcdserverpbLeaseLeasesRequest(data2)

	case 47:
		_ = FuzzetcdserverpbLeaseStatus(data2)

	case 48:
		_ = FuzzetcdserverpbLeaseLeasesResponse(data2)

	case 49:
		_ = FuzzetcdserverpbMember(data2)

	case 50:
		_ = FuzzetcdserverpbMemberAddRequest(data2)

	case 51:
		_ = FuzzetcdserverpbMemberAddResponse(data2)

	case 52:
		_ = FuzzetcdserverpbMemberRemoveRequest(data2)

	case 53:
		_ = FuzzetcdserverpbMemberRemoveResponse(data2)

	case 54:
		_ = FuzzetcdserverpbMemberUpdateRequest(data2)

	case 55:
		_ = FuzzetcdserverpbMemberUpdateResponse(data2)

	case 56:
		_ = FuzzetcdserverpbMemberListRequest(data2)

	case 57:
		_ = FuzzetcdserverpbMemberListResponse(data2)

	case 58:
		_ = FuzzetcdserverpbMemberPromoteRequest(data2)

	case 59:
		_ = FuzzetcdserverpbMemberPromoteResponse(data2)

	case 60:
		_ = FuzzetcdserverpbDefragmentRequest(data2)

	case 61:
		_ = FuzzetcdserverpbDefragmentResponse(data2)

	case 62:
		_ = FuzzetcdserverpbMoveLeaderRequest(data2)

	case 63:
		_ = FuzzetcdserverpbMoveLeaderResponse(data2)

	case 64:
		_ = FuzzetcdserverpbAlarmRequest(data2)

	case 65:
		_ = FuzzetcdserverpbAlarmMember(data2)

	case 66:
		_ = FuzzetcdserverpbAlarmResponse(data2)

	case 67:
		_ = FuzzetcdserverpbDowngradeRequest(data2)

	case 68:
		_ = FuzzetcdserverpbDowngradeResponse(data2)

	case 69:
		_ = FuzzetcdserverpbStatusRequest(data2)

	case 70:
		_ = FuzzetcdserverpbStatusResponse(data2)

	case 71:
		_ = FuzzetcdserverpbAuthEnableRequest(data2)

	case 72:
		_ = FuzzetcdserverpbAuthDisableRequest(data2)

	case 73:
		_ = FuzzetcdserverpbAuthStatusRequest(data2)

	case 74:
		_ = FuzzetcdserverpbAuthenticateRequest(data2)

	case 75:
		_ = FuzzetcdserverpbAuthUserAddRequest(data2)

	case 76:
		_ = FuzzetcdserverpbAuthUserGetRequest(data2)

	case 77:
		_ = FuzzetcdserverpbAuthUserDeleteRequest(data2)

	case 78:
		_ = FuzzetcdserverpbAuthUserChangePasswordRequest(data2)

	case 79:
		_ = FuzzetcdserverpbAuthUserGrantRoleRequest(data2)

	case 80:
		_ = FuzzetcdserverpbAuthUserRevokeRoleRequest(data2)

	case 81:
		_ = FuzzetcdserverpbAuthRoleAddRequest(data2)

	case 82:
		_ = FuzzetcdserverpbAuthRoleGetRequest(data2)

	case 83:
		_ = FuzzetcdserverpbAuthUserListRequest(data2)

	case 84:
		_ = FuzzetcdserverpbAuthRoleListRequest(data2)

	case 85:
		_ = FuzzetcdserverpbAuthRoleDeleteRequest(data2)

	case 86:
		_ = FuzzetcdserverpbAuthRoleGrantPermissionRequest(data2)

	case 87:
		_ = FuzzetcdserverpbAuthRoleRevokePermissionRequest(data2)

	case 88:
		_ = FuzzetcdserverpbAuthEnableResponse(data2)

	case 89:
		_ = FuzzetcdserverpbAuthDisableResponse(data2)

	case 90:
		_ = FuzzetcdserverpbAuthStatusResponse(data2)

	case 91:
		_ = FuzzetcdserverpbAuthenticateResponse(data2)

	case 92:
		_ = FuzzetcdserverpbAuthUserAddResponse(data2)

	case 93:
		_ = FuzzetcdserverpbAuthUserGetResponse(data2)

	case 94:
		_ = FuzzetcdserverpbAuthUserDeleteResponse(data2)

	case 95:
		_ = FuzzetcdserverpbAuthUserChangePasswordResponse(data2)

	case 96:
		_ = FuzzetcdserverpbAuthUserGrantRoleResponse(data2)

	case 97:
		_ = FuzzetcdserverpbAuthUserRevokeRoleResponse(data2)

	case 98:
		_ = FuzzetcdserverpbAuthRoleAddResponse(data2)

	case 99:
		_ = FuzzetcdserverpbAuthRoleGetResponse(data2)

	case 100:
		_ = FuzzetcdserverpbAuthRoleListResponse(data2)

	case 101:
		_ = FuzzetcdserverpbAuthUserListResponse(data2)

	case 102:
		_ = FuzzetcdserverpbAuthRoleDeleteResponse(data2)

	case 103:
		_ = FuzzetcdserverpbAuthRoleGrantPermissionResponse(data2)

	case 104:
		_ = FuzzetcdserverpbAuthRoleRevokePermissionResponse(data2)

	case 105:
		_ = FuzzmembershippbRaftAttributes(data2)

	case 106:
		_ = FuzzmembershippbAttributes(data2)

	case 107:
		_ = FuzzmembershippbMember(data2)

	case 108:
		_ = FuzzmembershippbClusterVersionSetRequest(data2)

	case 109:
		_ = FuzzmembershippbClusterMemberAttrSetRequest(data2)

	case 110:
		_ = FuzzmembershippbDowngradeInfoSetRequest(data2)

	case 111:
		_ = FuzzmvccpbKeyValue(data2)

	case 112:
		_ = FuzzmvccpbEvent(data2)

	case 113:
		_ = FuzzsnappbSnapshot(data2)

	case 114:
		_ = Fuzzv3electionpbCampaignRequest(data2)

	case 115:
		_ = Fuzzv3electionpbCampaignResponse(data2)

	case 116:
		_ = Fuzzv3electionpbLeaderKey(data2)

	case 117:
		_ = Fuzzv3electionpbLeaderRequest(data2)

	case 118:
		_ = Fuzzv3electionpbLeaderResponse(data2)

	case 119:
		_ = Fuzzv3electionpbResignRequest(data2)

	case 120:
		_ = Fuzzv3electionpbResignResponse(data2)

	case 121:
		_ = Fuzzv3electionpbProclaimRequest(data2)

	case 122:
		_ = Fuzzv3electionpbProclaimResponse(data2)

	case 123:
		_ = Fuzzv3lockpbLockRequest(data2)

	case 124:
		_ = Fuzzv3lockpbLockResponse(data2)

	case 125:
		_ = Fuzzv3lockpbUnlockRequest(data2)

	case 126:
		_ = Fuzzv3lockpbUnlockResponse(data2)

	case 127:
		_ = FuzzleasepbLease(data2)

	case 128:
		_ = FuzzleasepbLeaseInternalRequest(data2)

	case 129:
		_ = FuzzleasepbLeaseInternalResponse(data2)

	case 130:
		_ = FuzzwalpbRecord(data2)

	case 131:
		_ = FuzzwalpbSnapshot(data2)

	case 132:
		_ = FuzzrpcpbRequest(data2)

	case 133:
		_ = FuzzrpcpbSnapshotInfo(data2)

	case 134:
		_ = FuzzrpcpbResponse(data2)

	case 135:
		_ = FuzzrpcpbMember(data2)

	case 136:
		_ = FuzzrpcpbTester(data2)

	case 137:
		_ = FuzzrpcpbStresser(data2)

	case 138:
		_ = FuzzrpcpbEtcd(data2)

	case 139:
		_ = FuzzraftpbEntry(data2)

	case 140:
		_ = FuzzraftpbSnapshotMetadata(data2)

	case 141:
		_ = FuzzraftpbSnapshot(data2)

	case 142:
		_ = FuzzraftpbMessage(data2)

	case 143:
		_ = FuzzraftpbHardState(data2)

	case 144:
		_ = FuzzraftpbConfState(data2)

	case 145:
		_ = FuzzraftpbConfChange(data2)

	case 146:
		_ = FuzzraftpbConfChangeSingle(data2)

	case 147:
		_ = FuzzraftpbConfChangeV2(data2)

	}
	return 1
}

func FuzzauthpbUserAddOptions(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &authpb.UserAddOptions{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &authpb.UserAddOptions{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &authpb.UserAddOptions{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzauthpbUser(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &authpb.User{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &authpb.User{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &authpb.User{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzauthpbPermission(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &authpb.Permission{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &authpb.Permission{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &authpb.Permission{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzauthpbRole(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &authpb.Role{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &authpb.Role{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &authpb.Role{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.Request{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.Request{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.Request{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMetadata(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.Metadata{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.Metadata{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.Metadata{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbRequestHeader(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.RequestHeader{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.RequestHeader{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.RequestHeader{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbInternalRaftRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.InternalRaftRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.InternalRaftRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.InternalRaftRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbEmptyResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.EmptyResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.EmptyResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.EmptyResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbInternalAuthenticateRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.InternalAuthenticateRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.InternalAuthenticateRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.InternalAuthenticateRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbResponseHeader(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.ResponseHeader{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.ResponseHeader{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.ResponseHeader{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbRangeRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.RangeRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.RangeRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.RangeRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbRangeResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.RangeResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.RangeResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.RangeResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbPutRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.PutRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.PutRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.PutRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbPutResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.PutResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.PutResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.PutResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDeleteRangeRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DeleteRangeRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DeleteRangeRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DeleteRangeRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDeleteRangeResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DeleteRangeResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DeleteRangeResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DeleteRangeResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbRequestOp(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.RequestOp{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.RequestOp{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.RequestOp{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbResponseOp(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.ResponseOp{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.ResponseOp{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.ResponseOp{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbCompare(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.Compare{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.Compare{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.Compare{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbTxnRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.TxnRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.TxnRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.TxnRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbTxnResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.TxnResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.TxnResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.TxnResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbCompactionRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.CompactionRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.CompactionRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.CompactionRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbCompactionResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.CompactionResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.CompactionResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.CompactionResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbHashRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.HashRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.HashRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.HashRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbHashKVRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.HashKVRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.HashKVRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.HashKVRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbHashKVResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.HashKVResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.HashKVResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.HashKVResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbHashResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.HashResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.HashResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.HashResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbSnapshotRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.SnapshotRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.SnapshotRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.SnapshotRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbSnapshotResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.SnapshotResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.SnapshotResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.SnapshotResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbWatchRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.WatchRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.WatchRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.WatchRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbWatchCreateRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.WatchCreateRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.WatchCreateRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.WatchCreateRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbWatchCancelRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.WatchCancelRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.WatchCancelRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.WatchCancelRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbWatchProgressRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.WatchProgressRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.WatchProgressRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.WatchProgressRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbWatchResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.WatchResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.WatchResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.WatchResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseGrantRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseGrantRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseGrantRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseGrantRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseGrantResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseGrantResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseGrantResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseGrantResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseRevokeRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseRevokeRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseRevokeRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseRevokeRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseRevokeResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseRevokeResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseRevokeResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseRevokeResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseCheckpoint(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseCheckpoint{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseCheckpoint{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseCheckpoint{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseCheckpointRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseCheckpointRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseCheckpointRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseCheckpointRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseCheckpointResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseCheckpointResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseCheckpointResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseCheckpointResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseKeepAliveRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseKeepAliveRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseKeepAliveRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseKeepAliveRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseKeepAliveResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseKeepAliveResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseKeepAliveResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseKeepAliveResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseTimeToLiveRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseTimeToLiveRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseTimeToLiveRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseTimeToLiveRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseTimeToLiveResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseTimeToLiveResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseTimeToLiveResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseTimeToLiveResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseLeasesRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseLeasesRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseLeasesRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseLeasesRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseStatus(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseStatus{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseStatus{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseStatus{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbLeaseLeasesResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.LeaseLeasesResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.LeaseLeasesResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.LeaseLeasesResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMember(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.Member{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.Member{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.Member{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberAddRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberAddRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberAddRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberAddRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberAddResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberAddResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberAddResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberAddResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberRemoveRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberRemoveRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberRemoveRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberRemoveRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberRemoveResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberRemoveResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberRemoveResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberRemoveResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberUpdateRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberUpdateRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberUpdateRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberUpdateRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberUpdateResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberUpdateResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberUpdateResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberUpdateResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberListRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberListRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberListRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberListRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberListResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberListResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberListResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberListResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberPromoteRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberPromoteRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberPromoteRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberPromoteRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMemberPromoteResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MemberPromoteResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MemberPromoteResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MemberPromoteResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDefragmentRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DefragmentRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DefragmentRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DefragmentRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDefragmentResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DefragmentResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DefragmentResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DefragmentResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMoveLeaderRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MoveLeaderRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MoveLeaderRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MoveLeaderRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbMoveLeaderResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.MoveLeaderResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.MoveLeaderResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.MoveLeaderResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAlarmRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AlarmRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AlarmRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AlarmRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAlarmMember(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AlarmMember{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AlarmMember{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AlarmMember{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAlarmResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AlarmResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AlarmResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AlarmResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDowngradeRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DowngradeRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DowngradeRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DowngradeRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbDowngradeResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.DowngradeResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.DowngradeResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.DowngradeResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbStatusRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.StatusRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.StatusRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.StatusRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbStatusResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.StatusResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.StatusResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.StatusResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthEnableRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthEnableRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthEnableRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthEnableRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthDisableRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthDisableRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthDisableRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthDisableRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthStatusRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthStatusRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthStatusRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthStatusRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthenticateRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthenticateRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthenticateRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthenticateRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserAddRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserAddRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserAddRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserAddRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserGetRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserGetRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserGetRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserGetRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserDeleteRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserDeleteRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserDeleteRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserDeleteRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserChangePasswordRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserChangePasswordRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserChangePasswordRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserChangePasswordRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserGrantRoleRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserGrantRoleRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserGrantRoleRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserGrantRoleRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserRevokeRoleRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserRevokeRoleRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserRevokeRoleRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserRevokeRoleRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleAddRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleAddRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleAddRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleAddRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleGetRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleGetRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleGetRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleGetRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserListRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserListRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserListRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserListRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleListRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleListRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleListRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleListRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleDeleteRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleDeleteRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleDeleteRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleDeleteRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleGrantPermissionRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleGrantPermissionRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleGrantPermissionRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleGrantPermissionRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleRevokePermissionRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleRevokePermissionRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleRevokePermissionRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleRevokePermissionRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthEnableResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthEnableResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthEnableResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthEnableResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthDisableResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthDisableResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthDisableResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthDisableResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthStatusResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthStatusResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthStatusResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthStatusResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthenticateResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthenticateResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthenticateResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthenticateResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserAddResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserAddResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserAddResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserAddResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserGetResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserGetResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserGetResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserGetResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserDeleteResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserDeleteResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserDeleteResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserDeleteResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserChangePasswordResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserChangePasswordResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserChangePasswordResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserChangePasswordResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserGrantRoleResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserGrantRoleResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserGrantRoleResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserGrantRoleResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserRevokeRoleResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserRevokeRoleResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserRevokeRoleResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserRevokeRoleResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleAddResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleAddResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleAddResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleAddResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleGetResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleGetResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleGetResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleGetResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleListResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleListResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleListResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleListResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthUserListResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthUserListResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthUserListResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthUserListResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleDeleteResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleDeleteResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleDeleteResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleDeleteResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleGrantPermissionResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleGrantPermissionResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleGrantPermissionResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleGrantPermissionResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzetcdserverpbAuthRoleRevokePermissionResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &etcdserverpb.AuthRoleRevokePermissionResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &etcdserverpb.AuthRoleRevokePermissionResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &etcdserverpb.AuthRoleRevokePermissionResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbRaftAttributes(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.RaftAttributes{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.RaftAttributes{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.RaftAttributes{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbAttributes(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.Attributes{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.Attributes{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.Attributes{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbMember(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.Member{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.Member{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.Member{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbClusterVersionSetRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.ClusterVersionSetRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.ClusterVersionSetRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.ClusterVersionSetRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbClusterMemberAttrSetRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.ClusterMemberAttrSetRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.ClusterMemberAttrSetRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.ClusterMemberAttrSetRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmembershippbDowngradeInfoSetRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &membershippb.DowngradeInfoSetRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &membershippb.DowngradeInfoSetRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &membershippb.DowngradeInfoSetRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmvccpbKeyValue(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &mvccpb.KeyValue{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &mvccpb.KeyValue{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &mvccpb.KeyValue{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzmvccpbEvent(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &mvccpb.Event{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &mvccpb.Event{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &mvccpb.Event{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzsnappbSnapshot(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &snappb.Snapshot{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &snappb.Snapshot{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &snappb.Snapshot{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbCampaignRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.CampaignRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.CampaignRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.CampaignRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbCampaignResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.CampaignResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.CampaignResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.CampaignResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbLeaderKey(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.LeaderKey{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.LeaderKey{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.LeaderKey{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbLeaderRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.LeaderRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.LeaderRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.LeaderRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbLeaderResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.LeaderResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.LeaderResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.LeaderResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbResignRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.ResignRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.ResignRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.ResignRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbResignResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.ResignResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.ResignResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.ResignResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbProclaimRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.ProclaimRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.ProclaimRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.ProclaimRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3electionpbProclaimResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3electionpb.ProclaimResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3electionpb.ProclaimResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3electionpb.ProclaimResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3lockpbLockRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3lockpb.LockRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3lockpb.LockRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3lockpb.LockRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3lockpbLockResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3lockpb.LockResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3lockpb.LockResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3lockpb.LockResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3lockpbUnlockRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3lockpb.UnlockRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3lockpb.UnlockRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3lockpb.UnlockRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func Fuzzv3lockpbUnlockResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &v3lockpb.UnlockResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &v3lockpb.UnlockResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &v3lockpb.UnlockResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzleasepbLease(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &leasepb.Lease{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &leasepb.Lease{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &leasepb.Lease{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzleasepbLeaseInternalRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &leasepb.LeaseInternalRequest{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &leasepb.LeaseInternalRequest{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &leasepb.LeaseInternalRequest{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzleasepbLeaseInternalResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &leasepb.LeaseInternalResponse{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &leasepb.LeaseInternalResponse{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &leasepb.LeaseInternalResponse{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzwalpbRecord(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &walpb.Record{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &walpb.Record{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &walpb.Record{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzwalpbSnapshot(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &walpb.Snapshot{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &walpb.Snapshot{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &walpb.Snapshot{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbRequest(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Request{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Request{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Request{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbSnapshotInfo(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.SnapshotInfo{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.SnapshotInfo{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.SnapshotInfo{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbResponse(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Response{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Response{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Response{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbMember(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Member{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Member{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Member{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbTester(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Tester{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Tester{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Tester{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbStresser(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Stresser{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Stresser{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Stresser{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzrpcpbEtcd(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &rpcpb.Etcd{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &rpcpb.Etcd{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &rpcpb.Etcd{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbEntry(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.Entry{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.Entry{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.Entry{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbSnapshotMetadata(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.SnapshotMetadata{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.SnapshotMetadata{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.SnapshotMetadata{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbSnapshot(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.Snapshot{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.Snapshot{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.Snapshot{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbMessage(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.Message{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.Message{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.Message{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbHardState(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.HardState{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.HardState{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.HardState{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbConfState(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.ConfState{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.ConfState{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.ConfState{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbConfChange(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.ConfChange{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.ConfChange{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.ConfChange{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbConfChangeSingle(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.ConfChangeSingle{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.ConfChangeSingle{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.ConfChangeSingle{}
	err = s3.Unmarshal(newBytes)
	return err
}


func FuzzraftpbConfChangeV2(data []byte) error {
	f := fuzz.NewConsumer(data)
	s := &raftpb.ConfChangeV2{}
	err := f.GenerateStruct(s)
	if err != nil {
		return err
	}
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	s2 := &raftpb.ConfChangeV2{}
	err = s2.Unmarshal(b)
	if err != nil {
		return err
	}
	newBytes, err := f.GetBytes()
	if err != nil {
		return err
	}
	s3 := &raftpb.ConfChangeV2{}
	err = s3.Unmarshal(newBytes)
	return err
}
